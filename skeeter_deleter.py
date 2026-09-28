import argparse
import dateutil.parser
import httpx
import logging
import magic
import os
import rich.progress
from atproto import CAR, Client, models
from atproto_core.cid import CID
from atproto_client.request import Request
from atproto_client.exceptions import AtProtocolError
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path

logging.basicConfig(filename='skeeter_deleter.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(message)s')

class PostQualifier(models.AppBskyFeedDefs.PostView):
    """
    This class wraps the ATProto PostView instance of a post, as returned from a list of posts
    The rationale here is to separate post-related business logic (e.g. age heuristics, virality)
    from feed-related business logic
    
    These filters are customizable, or new filters can be added here
    """
    def is_viral(self, viral_threshold) -> bool:
        """
        Check if the post is viral based on the repost count.
        Args:
            viral_threshold (int): The threshold for considering a post viral.
        Returns:
            bool: True if the post is viral, False otherwise.
        """
        if viral_threshold == 0:
            return False
        return self.repost_count >= viral_threshold

    def is_stale(self, stale_threshold, now) -> bool:
        """
        Check if the post is stale based on its age.
        Args:
            stale_threshold (int): The threshold for considering a post stale.
            now (datetime): The current time.
        Returns:
            bool: True if the post is stale, False otherwise.
        """
        if stale_threshold == 0:
            return False
        return dateutil.parser.parse(self.record.created_at).replace(tzinfo=timezone.utc) <= \
            now - timedelta(days=stale_threshold)

    def is_protected_domain(self, domains_to_protect) -> bool:
        """
        Check if the post contains links to protected domains.
        Args:
            domains_to_protect (list): List of domains to protect.
        Returns:
            bool: True if the post contains links to protected domains, False otherwise.
        """
        return hasattr(self.embed, "external") and \
            any([uri in self.embed.external.uri for uri in domains_to_protect])
        
    def is_self_liked(self, self_likes) -> bool:
        """
        Check if the author of the post has liked it.

        Args:
            self_likes (list): a list of self-liked posts, extracted from
                               the feed archive
        Returns:
            bool: True if the author has liked the post, False otherwise.
        """
        return self.uri in [post['subject']['uri'] for post in self_likes]
    
    def __init__(self, client : Client):
        super(PostQualifier, self).__init__()
        self._init_PostQualifier(client)
    
    def _init_PostQualifier(self, client : Client):
        self.client = client
        self._like_uri = None    # AT URI of the user's like record (from listRecords)
        self._repost_uri = None  # AT URI of the user's repost record (from listRecords)

    def delete_like(self):
        """
        Remove a like from a post
        """
        like_uri = self._like_uri or (self.viewer.like if self.viewer else None)
        if like_uri is None:
            logging.warning(f"Skipping unlike for {self.uri}: no like record URI found")
            return
        try:
            logging.info(f"Removing like: {like_uri}")
            self.client.delete_like(like_uri)
        except AtProtocolError as e:
            logging.error(f"Error while unliking {like_uri}: {e}")
        except Exception as e:
            logging.error(f"An error occurred while unliking: {e}")

    def remove(self):
        """
        Remove a repost or delete an authored post
        """
        if self.author.did != self.client.me.did:
            repost_uri = self._repost_uri or (self.viewer.repost if self.viewer else None)
            if repost_uri is None:
                logging.warning(f"Skipping unrepost for {self.uri}: no repost record URI found")
                return
            try:
                logging.info(f"Removing repost: {repost_uri}")
                self.client.unrepost(repost_uri)
            except AtProtocolError as e:
                logging.error(f"Error during unreposting {repost_uri}: {e}")
            except Exception as e:
                logging.error(f"An error occurred during unreposting: {e}")
        else:
            try:
                logging.info(f"Removing post: {self.uri}")
                self.client.delete_post(self.uri)
            except AtProtocolError as e:
                logging.error(f"Error during deletion of {self.uri}: {e}")
            except Exception as e:
                logging.error(f"An error occurred during deletion: {e}")

    @staticmethod
    def to_delete(viral_threshold, stale_threshold, domains_to_protect, now, self_likes, post):
        """
        Determine if a post should be deleted.
        Args:
            viral_threshold (int): The threshold for considering a post viral.
            stale_threshold (int): The threshold for considering a post stale.
            domains_to_protect (list): List of domains to protect.
            now (datetime): The current time.
            self_likes (list): List of self-liked posts extracted from
                               the feed archive
            post (PostQualifier): The post to evaluate.
        Returns:
            bool: True if the post should be deleted, False otherwise.
        """
        if (post.is_viral(viral_threshold) or post.is_stale(stale_threshold, now)) and \
            not post.is_protected_domain(domains_to_protect) and \
            not post.is_self_liked(self_likes):
            return True
        return False

    @staticmethod
    def to_remove(stale_threshold, now, post):
        """
        Determine if a post should be unliked.
        Args:
            stale_threshold (int): The threshold for considering a post stale.
            now (datetime): The current time.
            post (PostQualifier): The post to evaluate.
        Returns:
            bool: True if the post should be unliked, False otherwise.
        """
        return post.is_stale(stale_threshold, now)
    
    @staticmethod
    def cast(client : Client, post : models.AppBskyFeedDefs.PostView):
        """
        Cast a post to a PostQualifier instance.
        Args:
            client (Client): The ATProto client.
            post (models.AppBskyFeedDefs.FeedViewPost): The post to cast.
        Returns:
            PostQualifier: The casted post.
        """
        post.__class__ = PostQualifier
        post._init_PostQualifier(client)
        return post
    
@dataclass
class Credentials:
    login: str
    password: str

    dict = asdict


class RequestCustomTimeout(Request):
    def __init__(self, timeout: httpx.Timeout = httpx.Timeout(120), *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._client = httpx.Client(follow_redirects=True, timeout=timeout)


class SkeeterDeleter:
    @staticmethod
    def chunker(seq, size : int):
        """
        Break a iterable into segments of a given size

        Args:
            seq (iterable): The iterable to be broken into chunks
            size (int): The chunk size
        Returns:
            list[iterable]: List of iterables of length at most size
        """
        return (seq[pos:pos + size] for pos in range(0, len(seq), size))
    
    @staticmethod
    def extract_feed_item(archive, block):
        """
        Converts feed items from the repo with various structures into consistent blocks

        Args:
            archive: The repository as a binary CAR
            block: The block to extract
        Returns:
            block: A decoded block
        """
        if '$type' in block:
            return block
        elif 'e' in block and len(block['e']) > 0:
            return archive.blocks.get(CID.decode(block['e'][0]['v']))
        else:
            return block

    def gather_likes(self,
                     stale_threshold,
                     now,
                     **kwargs) -> list[PostQualifier]:
        # Use listRecords as the single authoritative source for like records.
        # This correctly identifies self-liked posts (to protect from deletion)
        # and gives us the AT URI of each like record (needed to delete it).
        like_uri_map = {}  # subject_uri -> like_record_uri
        cursor = None
        while True:
            try:
                resp = self.client.com.atproto.repo.list_records(params={
                    'repo': self.client.me.did,
                    'collection': 'app.bsky.feed.like',
                    'cursor': cursor,
                    'limit': 100,
                })
                for r in resp.records:
                    subject_uri = (r.value.subject.uri
                                   if hasattr(r.value, 'subject')
                                   else r.value.get('subject', {}).get('uri'))
                    if subject_uri:
                        like_uri_map[subject_uri] = r.uri
                cursor = resp.cursor
                if not cursor:
                    break
            except Exception as e:
                logging.error(f"An error occurred while fetching like record URIs: {e}")
                break

        # Self-likes: likes of the user's own posts, identified by DID in the subject URI.
        # These protect matching authored posts from deletion.
        self_likes = [{'subject': {'uri': uri}} for uri in like_uri_map
                      if self.client.me.did in uri]

        # Other likes: likes of posts by other accounts, candidates for unliking.
        other_like_uris = [uri for uri in like_uri_map if self.client.me.did not in uri]

        # The API limits the get_posts method to 25 results at a time.
        to_unlike = []
        for batch in self.chunker(other_like_uris, 25):
            try:
                posts_to_unlike = self.client.get_posts(uris=batch)
                for post in posts_to_unlike.posts:
                    pq = PostQualifier.cast(self.client, post)
                    pq._like_uri = like_uri_map.get(pq.uri)
                    if PostQualifier.to_remove(stale_threshold, now, pq):
                        to_unlike.append(pq)
            except AtProtocolError as e:
                logging.error(f"An HTTP error occured while fetching likes: {e}")
            except Exception as e:
                logging.error(f"An error occured while fetching likes: {e}")

        return self_likes, to_unlike

    def gather_reposts(self,
                       viral_threshold,
                       stale_threshold,
                       domains_to_protect,
                       now,
                       self_likes,
                       **kwargs) -> list[PostQualifier]:
        # Use listRecords to get repost records with their AT URIs directly.
        # This avoids relying on viewer.repost from get_posts(), which can be None
        # when the AppView is out of sync with the repo or when posts are deleted.
        all_reposts = []  # list of {'subject_uri': str, 'repost_uri': str}
        cursor = None
        while True:
            try:
                resp = self.client.com.atproto.repo.list_records(params={
                    'repo': self.client.me.did,
                    'collection': 'app.bsky.feed.repost',
                    'cursor': cursor,
                    'limit': 100,
                })
                for r in resp.records:
                    subject_uri = (r.value.subject.uri
                                   if hasattr(r.value, 'subject')
                                   else r.value.get('subject', {}).get('uri'))
                    if subject_uri:
                        all_reposts.append({'subject_uri': subject_uri, 'repost_uri': r.uri})
                cursor = resp.cursor
                if not cursor:
                    break
            except Exception as e:
                logging.error(f"An error occurred while fetching repost records: {e}")
                break

        to_unrepost = []
        for batch in self.chunker(all_reposts, 25):
            try:
                uri_to_repost_uri = {x['subject_uri']: x['repost_uri'] for x in batch}
                posts_to_remove = self.client.get_posts(uris=list(uri_to_repost_uri.keys()))
                for post in posts_to_remove.posts:
                    pq = PostQualifier.cast(self.client, post)
                    pq._repost_uri = uri_to_repost_uri.get(pq.uri)
                    if PostQualifier.to_delete(viral_threshold, stale_threshold,
                                              domains_to_protect, now, self_likes, pq):
                        to_unrepost.append(pq)
            except AtProtocolError as e:
                logging.error(f"An HTTP error occured while fetching reposts: {e}")
            except Exception as e:
                logging.error(f"An error occured while fetching reposts: {e}")
        return to_unrepost

    def gather_posts_to_delete(self,
                               viral_threshold,
                               stale_threshold,
                               domains_to_protect,
                               now,
                               self_likes,
                               **kwargs) -> list[PostQualifier]:
        cursor = None
        to_delete = []
        while True:
            try:
                posts = self.client.get_author_feed(self.client.me.handle,
                                                    cursor=cursor,
                                                    filter="from:me",
                                                    limit=100)
                delete_test = partial(PostQualifier.to_delete,
                                    viral_threshold,
                                    stale_threshold,
                                    domains_to_protect,
                                    now,
                                    self_likes)
                to_delete.extend(list(filter(
                    delete_test,
                    map(partial(PostQualifier.cast, self.client),
                        [x.post for x in posts.feed]
                    )
                )))

                cursor = posts.cursor
                if self.verbosity > 0:
                    print(f"Cursor at: {cursor}")
            except AtProtocolError as e:
                # Stop paging: the cursor didn't advance, so retrying would loop forever
                logging.error(f"An HTTP error occured while fetching posts: {e}")
                break
            except Exception as e:
                logging.error(f"An error occured while fetching posts: {e}")
                break
            if cursor == None:
                break
        return to_delete

    def dry_run_summary(self) -> None:
        """Print a summary of what would be deleted/unliked/unreposted without taking any action."""
        n_unlike = len(self.to_unlike)
        n_delete = sum(1 for p in self.to_delete if p.author.did == self.client.me.did)
        n_unrepost = sum(1 for p in self.to_delete if p.author.did != self.client.me.did)

        print(f"\n=== Dry-run summary (no changes made) ===")
        print(f"  Likes to remove : {n_unlike}")
        for post in self.to_unlike:
            print(f"    [like]    {post.record.created_at}  @{post.author.handle}  {post.uri}")
        print(f"  Reposts to undo : {n_unrepost}")
        for post in self.to_delete:
            if post.author.did != self.client.me.did:
                print(f"    [repost]  {post.record.created_at}  @{post.author.handle}  {post.uri}")
        print(f"  Posts to delete : {n_delete}")
        for post in self.to_delete:
            if post.author.did == self.client.me.did:
                text_preview = (post.record.text[:80].replace('\n', ' ')
                                if hasattr(post.record, 'text') and post.record.text else '')
                print(f"    [post]    {post.record.created_at}  {text_preview!r}")
        print()
        logging.info(f"Dry-run: would unlike {n_unlike}, unrepost {n_unrepost}, delete {n_delete}")

    def batch_unlike_posts(self) -> None:
        logging.info(f"Unliking {len(self.to_unlike)} post{'' if len(self.to_unlike) == 1 else 's'}")
        if self.verbosity > 0:
            print(f"Unliking {len(self.to_unlike)} post{'' if len(self.to_unlike) == 1 else 's'}")
        for post in rich.progress.track(self.to_unlike):
            logging.info(f"Unliking: {post.uri} by {post.author.handle}, CID: {post.cid}")
            if self.verbosity == 2:
                print(f"Unliking: {post.uri} by {post.author.handle}, CID: {post.cid}")
            post.delete_like()

    def batch_delete_posts(self) -> None:
        logging.info(f"Deleting {len(self.to_delete)} post{'' if len(self.to_delete) == 1 else 's'}")
        if self.verbosity > 0:
            print(f"Deleting {len(self.to_delete)} post{'' if len(self.to_delete) == 1 else 's'}")
        for post in rich.progress.track(self.to_delete):
            logging.info(f"Deleting: {post.record.text} on {post.record.created_at}, CID: {post.cid}")
            if self.verbosity == 2:
                print(f"Deleting: {post.record.text} on {post.record.created_at}, CID: {post.cid}")
            post.remove()
            
    def archive_repo(self, now, **kwargs):
        repo = self.client.com.atproto.sync.get_repo(params={'did': self.client.me.did})
        clean_user_did = self.client.me.did.replace(":", "_")
        Path(f"archive/{clean_user_did}/_blob/").mkdir(parents=True, exist_ok=True)
        print("Archiving posts...")
        clean_now = now.isoformat().replace(':','_')
        with open(f"archive/{clean_user_did}/bsky-archive-{clean_now}.car", "wb") as f:
            f.write(repo)

        cursor = None
        print("Downloading and archiving media...")
        blob_cids = []
        while True:
            blob_page = self.client.com.atproto.sync.list_blobs(params={'did': self.client.me.did, 'cursor': cursor})
            blob_cids.extend(blob_page.cids)
            cursor = blob_page.cursor
            if not cursor:
                break
        for cid in rich.progress.track(blob_cids):
            blob = self.client.com.atproto.sync.get_blob(params={'cid': cid, 'did': self.client.me.did})
            type = magic.from_buffer(blob, 2048)
            ext = ".jpeg" if type == "image/jpeg" else ""
            with open(f"archive/{clean_user_did}/_blob/{cid}{ext}", "wb") as f:
                if self.verbosity == 2:
                    print(f"Saving {cid}{ext}")
                f.write(blob)

        return repo

    def __init__(self,
                 credentials : Credentials,
                 viral_threshold : int=0,
                 stale_threshold : int=0,
                 domains_to_protect : list[str]=[],
                 fixed_likes_cursor : str=None,
                 verbosity : int=0,
                 autodelete : bool=False,
                 dry_run : bool=False,
                 min_posts_to_keep : int=10):
        self.client = Client(request=RequestCustomTimeout())
        self.client.login(**credentials.dict())

        # the parameters are a mess, sorry, this is a to-fix
        params = {
            'viral_threshold': viral_threshold,
            'stale_threshold': stale_threshold,
            'domains_to_protect': domains_to_protect,
            'fixed_likes_cursor': fixed_likes_cursor,
            'now': datetime.now(timezone.utc),
        }
        self.verbosity = verbosity
        self.autodelete = autodelete
        self.dry_run = dry_run

        self.archive_repo(**params)

        profile = self.client.get_profile(self.client.me.handle)
        current_count = profile.posts_count or 0
        print(f"Account @{self.client.me.handle} has {current_count} post{'' if current_count == 1 else 's'} total.")

        self_likes, self.to_unlike = self.gather_likes(**params)
        print(f"Found {len(self.to_unlike)} post{'' if len(self.to_unlike) == 1 else 's'} to unlike.")
        print(f"  (Protecting {len(self_likes)} self-liked post{'' if len(self_likes) == 1 else 's'} from deletion.)")

        to_unrepost = self.gather_reposts(self_likes=self_likes, **params)
        print(f"Found {len(to_unrepost)} post{'' if len(to_unrepost) == 1 else 's'} to unrepost.")

        self.to_delete = self.gather_posts_to_delete(self_likes=self_likes, **params)
        print(f"Found {len(self.to_delete)} post{'' if len(self.to_delete) == 1 else 's'} to delete.")

        self.to_delete.extend(to_unrepost)

        # Enforce minimum post count: trim the most-recent authored posts from
        # to_delete so the account never drops below min_posts_to_keep.
        if min_posts_to_keep > 0:
            authored = [p for p in self.to_delete if p.author.did == self.client.me.did]
            would_remain = current_count - len(authored)
            if would_remain < min_posts_to_keep:
                to_protect = min_posts_to_keep - would_remain
                # Sort authored posts newest-first and protect the most recent ones.
                authored_sorted = sorted(
                    authored,
                    key=lambda p: p.record.created_at,
                    reverse=True
                )
                protected = set(id(p) for p in authored_sorted[:to_protect])
                removed = len(protected)
                self.to_delete = [p for p in self.to_delete if id(p) not in protected]
                print(f"  (Keeping {removed} recent post{'' if removed == 1 else 's'} to stay above the {min_posts_to_keep}-post minimum.)")


    def unlike(self):
        if self.dry_run:
            return
        n_unlike = len(self.to_unlike)
        if n_unlike == 0:
            print("Nothing to unlike.")
            return
        prompt = None
        while not self.autodelete and prompt not in ("Y", "n"):
            prompt = input(f"""
Proceed to unlike {n_unlike} post{'' if n_unlike == 1 else 's'}? WARNING: THIS IS DESTRUCTIVE AND CANNOT BE UNDONE. Y/n: """)
        if self.autodelete or prompt == "Y":
            sd.batch_unlike_posts()

    def delete(self):
        if self.dry_run:
            return
        n_delete = len(self.to_delete)
        if n_delete == 0:
            print("Nothing to delete.")
            return
        prompt = None
        while not self.autodelete and prompt not in ("Y", "n"):
            prompt = input(f"""
Proceed to delete {n_delete} post{'' if n_delete == 1 else 's'}? WARNING: THIS IS DESTRUCTIVE AND CANNOT BE UNDONE. Y/n: """)
        if self.autodelete or prompt == "Y":
            sd.batch_delete_posts()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-l", "--max-reposts", help="""The upper bound of the number of reposts a post can have before it is deleted.
Ignore or set to 0 to not set an upper limit. This feature deletes posts that are going viral, which can reduce harassment.
Defaults to 0.""", default=0, type=int)
    parser.add_argument("-s", "--stale-limit", help="""The upper bound of the age of a post in days before it is deleted.
Ignore or set to 0 to not set an upper limit. This feature deletes old posts that may be taken out of context or selectively
misinterpreted, reducing potential harassment. Defaults to 0.""", default=0, type=int)
    parser.add_argument("-d", "--domains-to-protect", help="""A comma separated list of domain names to protect. Posts linking to
domains in this list will not be auto-deleted regardless of age or virality. Default is empty.""", default="")
    parser.add_argument("-c", "--fixed-likes-cursor", help="""A complex setting. ATProto pagination through is awkward, and
it will page through the entire history of your account even if there are no likes to be found. This can make the process take
a long time to complete. If you have already purged likes, it's possible to simply set a token at a reasonable point in the recent
past which will terminate the search. To list the tokens, run -vv mode. Tokens are short alphanumeric strings. Default empty.""",
default="")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", help="""Show more information about what is happening.""",
                           action="store_true")
    verbosity.add_argument("-vv", "--very-verbose", help="""Show granular information about what is happening.""",
                           action="store_true")
    parser.add_argument("-y", "--yes", help="""Ignore warning prompts for deletion. Necessary for running in automation.""",
                        action="store_true", default=False)
    parser.add_argument("-n", "--dry-run", help="""Show a summary of posts, likes, and boosts that would be deleted without
making any changes. Useful for verifying settings before running for real.""",
                        action="store_true", default=False)
    parser.add_argument("-m", "--min-posts", help="""The minimum number of your own posts to keep on the account. Deletion will
preserve the most recent posts needed to stay at or above this count. Set to 0 to disable.
Defaults to 10.""", default=10, type=int)
    args = parser.parse_args()

    creds = Credentials(os.environ["BLUESKY_USERNAME"],
                        os.environ["BLUESKY_PASSWORD"])
    verbosity = 0
    if args.verbose:
        verbosity = 1
    elif args.very_verbose:
        verbosity = 2
    params = {
        'viral_threshold': max([0, args.max_reposts]),
        'stale_threshold': max([0, args.stale_limit]),
        'domains_to_protect': ([] if args.domains_to_protect == ""
                               else [s.strip() 
                                     for s in args.domains_to_protect.split(",")]),
        'fixed_likes_cursor': args.fixed_likes_cursor,
        'verbosity': verbosity,
        'autodelete': args.yes,
        'dry_run': args.dry_run,
        'min_posts_to_keep': max(0, args.min_posts),
    }

    sd = SkeeterDeleter(credentials=creds, **params)
    if sd.dry_run:
        sd.dry_run_summary()
    else:
        sd.unlike()
        sd.delete()
