{-# LANGUAGE OverloadedStrings, DefaultSignatures, MultiParamTypeClasses, FunctionalDependencies #-}
module Web.Authenticate.SQRL.Client where

import Web.Authenticate.SQRL.Types
import Web.Authenticate.SQRL.SecureStorage
import Web.Authenticate.SQRL.Client.Types

import Data.Word (Word16)

--import Crypto.Random
import Data.ByteString (ByteString)
import Data.Byteable
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Maybe (fromMaybe)
--import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
--import qualified Data.ByteString.Base64.URL as B64U
--import qualified Crypto.Ed25519.Exceptions as ED25519
import qualified Crypto.Hash
import Control.Applicative
import Control.Monad ((>=>))
import Control.Exception (toException)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Catch (MonadThrow, throwM, MonadCatch, catch)
import Crypto.Random

import System.IO.Unsafe (unsafePerformIO)

newtype SQRLClient clnt m t = SQRLClient (clnt -> m (clnt, t))
--type SQRLClientIO clnt t = SQRLClient clnt IO t


instance (SQRLClientM clnt m) => Functor (SQRLClient clnt m) where
  fmap f (SQRLClient x) = let f' (s, t) = (s, f t) in SQRLClient $ \s' -> fmap f' (x s')

instance (SQRLClientM clnt m) => Monad (SQRLClient clnt m) where
  return x = SQRLClient $ \s -> return (s,x)
  (SQRLClient fx) >>= ffy = SQRLClient $ fx >=> \(s', y) -> readClientError s' >>= \ce -> case ce of { ClientErrNone -> let (SQRLClient fy) = ffy y in fy s' ; _ -> return (s', error $ "Monad<SQRLClient clnt m>.(>>=): " ++ show ce) }
  (SQRLClient fx) >> (SQRLClient fy) = SQRLClient $ fx >=> \(s', _) -> readClientError s' >>= \ce -> case ce of { ClientErrNone -> fy s' ; _ -> return (s', error $ "Monad<SQRLClient clnt m>.(>>): " ++ show ce) }
  fail err = fmap (const $ error $ "Monad<SQRLCLient clnt m>.fail: " ++ err) (setClientError (ClientErrOther err))

instance (SQRLClientM clnt m) => Applicative (SQRLClient clnt m) where
  pure x = SQRLClient $ \s -> return (s, x)
  (SQRLClient ff) <*> (SQRLClient xf) = SQRLClient $ ff >=> \(s', f) -> readClientError s' >>= \ce -> case ce of { ClientErrNone -> xf s' >>= \(s'', x) -> return (s'', f x) ; _ -> return (s', error $ "Applicative<SQRLClient clnt m>.(<*>): " ++ show ce) }
  (SQRLClient fx) <*  (SQRLClient fy) = SQRLClient $ fx >=> \(s', x) -> readClientError s' >>= \ce -> case ce of { ClientErrNone -> fy s' >>= \(s'', _) -> return (s'', x) ; _ -> return (s', error $ "Applicative<SQRLClient clnt m>.(<*): " ++ show ce) }
  (SQRLClient fx)  *> (SQRLClient fy) = SQRLClient $ fx >=> \(s', _) -> readClientError s' >>= \ce -> case ce of { ClientErrNone -> fy s' >>= \(s'', y) -> return (s'', y) ; _ -> return (s', error $ "Applicative<SQRLClient clnt m>.(*>): " ++ show ce) }

instance (SQRLClientM clnt m) => Alternative (SQRLClient clnt m) where
  empty = SQRLClient $ \s -> return (s, error "Alternative<SQRLClient clnt m>.empty: used the result from 'empty' with SQRLClient")
  (SQRLClient f0) <|> (SQRLClient f1) = SQRLClient $ \s -> do
    r@(s0, _) <- f0 s
    er  <- readClientError s0
    case er of
     ClientErrNone -> return r
     _ -> f1 s


(<||>) :: (SQRLClientM clnt m) => SQRLClient clnt m a -> (ClientErr -> SQRLClient clnt m a) -> SQRLClient clnt m a
(<||>) (SQRLClient ff) ef = SQRLClient $ \s -> do
  er0 <- readClientError s
  case er0 of
   ClientErrNone -> do
     r@(s', _) <- ff s
     err <- readClientError s'
     case err of
      ClientErrNone -> return r
      e -> let SQRLClient ef' = ef e in ef' s
   e -> let SQRLClient ef' = ef e
            SQRLClient tce = takeClientError
        in tce s >>= \(s0, _) -> ef' s0

(<<||) :: (SQRLClientM clnt m) => (ClientErr -> SQRLClient clnt m a) -> SQRLClient clnt m a -> SQRLClient clnt m a
(<<||) = flip (<||>)

instance (SQRLClientM clnt m) => MonadThrow (SQRLClient clnt m) where
  throwM e = SQRLClient $ \s -> do
    (s', _) <- runClient' s (setClientError (ClientErrThrown (toException e)))
    unsafePerformIO (putStrLn $ "TRACE: Exception thrown by SQRLClient: " ++ show e) `seq` return ()
    return (s', error $ "MonadThrow.throwM: used the result from 'throwM' with SQRLClient. (Exception was " ++ show e ++ ")")

instance (SQRLClientM clnt m, MonadCatch m) => MonadCatch (SQRLClient clnt m) where
--catch :: Exception e => m a -> (e -> m a) -> m a
  catch (SQRLClient ma) ef = SQRLClient $
    \s -> ma s `catch` \e -> let (SQRLClient eh) = ef e in
      (unsafePerformIO (putStrLn $ "TRACE: Exception catched by SQRLClient: " ++ show e) `seq` return ()) >>
      eh s

instance (MonadIO m, SQRLClientM clnt m) => MonadIO (SQRLClient clnt m) where
  liftIO f = SQRLClient $ \s -> (,) s <$> liftIO f

-- | Modify the client state.
modifyClient :: Monad m => (clnt -> clnt) -> SQRLClient clnt m ()
modifyClient f = SQRLClient (return . flip (,) () . f)

-- | Do some action with the client.
sqrlClient :: (clnt -> m (clnt, t)) -> SQRLClient clnt m t
sqrlClient = SQRLClient

-- | Do some action with the client without modifying the state.
--
-- Actions in the IO monad are discouraged unless they are transactional due to risk of the client getting out of sync.
sqrlClient' :: Functor m => (clnt -> m t) -> SQRLClient clnt m t
sqrlClient' f = SQRLClient $ \clnt -> (,) clnt <$> f clnt

-- | Run some action with a client and return the result.
runClient :: Functor m => clnt -> SQRLClient clnt m t -> m t
runClient clnt (SQRLClient f) = snd <$> f clnt

-- | Run some action with a client and return both the updated client state as well as the result.
runClient' :: clnt -> SQRLClient clnt m t -> m (clnt, t)
runClient' clnt (SQRLClient f) = f clnt

-- | Monadic return of the client state.
getClientState :: (Monad m) => SQRLClient clnt m clnt
getClientState = SQRLClient $ \clnt -> return (clnt, clnt)


class (Monad m, Functor m) => SQRLClientM clnt m | clnt -> m where
  -- | The name of this client.
  sqrlClientName :: clnt -> Text
  -- | The author(s) of this client.
  sqrlClientAuthor :: clnt -> Text
  -- | The email address, twitter handle, etc. to use to contact the developer(s) and/or publisher(s).
  sqrlClientContact :: clnt -> Text
  -- | The version of this client.
  sqrlClientVersion :: clnt -> Text
  -- | The versions of the SQRL protocol this client supports. (Defaults to version 1 only.)
  sqrlVersion :: clnt -> SQRLVersion
  sqrlVersion _ = sqrlVersion1
  -- | Sign a full client post.
  sqrlSignPost :: SQRLUrl -> SQRLClientPost a -> SQRLClient clnt m (SQRLClientPost a)
  sqrlSignPost = sqrlSignPost'
  -- | Sign blobs of data for a single domain using the current identity.
  sqrlSign :: SQRLUrl -> SQRLClient clnt m (IdentityKey, ByteString -> IdentitySignature)
  default sqrlSign :: MonadIO m => SQRLUrl -> SQRLClient clnt m (IdentityKey, ByteString -> IdentitySignature)
  sqrlSign = sqrlSign'
  -- | Sign blobs of data for a single domain using the previous identity.
  sqrlSignPrevious :: SQRLUrl -> SQRLClient clnt m (Maybe (IdentityKey, ByteString -> IdentitySignature))
  default sqrlSignPrevious :: MonadIO m => SQRLUrl -> SQRLClient clnt m (Maybe (IdentityKey, ByteString -> IdentitySignature))
  sqrlSignPrevious = sqrlSignPrevious'
  -- | The private key of the current identity for a single domain.
  sqrlIdentityKey :: SQRLUrl -> SQRLClient clnt m DomainIdentityKey
  -- | The private key of the previous identity for a single domain.
  sqrlIdentityKeyPrevious :: SQRLUrl -> SQRLClient clnt m (Maybe DomainIdentityKey)
  -- | Lets the user choose the profile to use when executing a client session.
  sqrlChooseProfile :: Text                  -- ^ short description why a profile is to be selected
                    -> SQRLClient clnt m ()  -- ^ action for the selected profile
                    -> m ()
  default sqrlChooseProfile :: (SecureStorageProfile clnt m) => Text -> SQRLClient clnt m () -> m ()
  sqrlChooseProfile = sqrlChooseProfile'
  -- | The name of the chosen profile.
  sqrlProfileName :: SQRLClient clnt m (Maybe Text)
  default sqrlProfileName :: (SecureStorageProfile clnt m) => SQRLClient clnt m (Maybe Text)
  sqrlProfileName = sqrlProfileName'
  -- | Request the client to create a new profile.
  sqrlCreateProfile :: SQRLClient clnt m () -> Text -> Password -> m ()
  default sqrlCreateProfile :: (SecureStorageProfile clnt m) => SQRLClient clnt m () -> Text -> Password -> m ()
  sqrlCreateProfile = sqrlCreateProfile'
  -- | Display some options to the user.
  sqrlAskClient :: (AskResponse -> SQRLClient clnt m ()) -> SQRLClient clnt m () -> SQRLAsk -> SQRLUrl -> SQRLServerData ByteString -> SQRLClient clnt m ()
  -- | Display login information to the user.
  sqrlLoginAccount :: (SQRLCommandAction -> SQRLClient clnt m ()) -> SQRLClient clnt m () -> SQRLUrl -> SQRLServerData ByteString -> SQRLClient clnt m ()
  -- | Ask the user to associate the account.
  sqrlAccountAssociation :: SQRLClient clnt m () -> SQRLClient clnt m () -> SQRLUrl -> SQRLServerData ByteString -> SQRLClient clnt m ()
  -- | Request deletion of any sensitive data.
  sqrlClearSensitive :: SQRLClient clnt m ()
  -- | Request deletion of any data protected by a simplified hint.
  sqrlClearHint :: SQRLClient clnt m ()
  -- | Reads and removes any error associated to this state.
  takeClientError :: SQRLClient clnt m ClientErr
  takeClientError = SQRLClient $ \s -> readClientError s >>= \x -> let SQRLClient f = setClientError ClientErrNone in f s >>= \(s', _) -> return (s', x)
  -- | Reads, but does not remove, any error associated to this state.
  readClientError :: clnt -> m ClientErr
  -- | Sets the error associated to this state.
  setClientError :: ClientErr -> SQRLClient clnt m ()
  -- | Dictates how keys should be generated.
  randomKeyGenerator :: SQRLClient clnt m RandomLockKey
  default randomKeyGenerator :: (MonadIO m, Functor m) => SQRLClient clnt m RandomLockKey
  randomKeyGenerator = SQRLClient $ \x -> (,) x <$> liftIO randomKeyGenerator'
  -- | Generate a 'ServerUnlockKey' and a 'VerifyUnlockKey'.
  -- These should be generated using the @Identity Lock File@ and 'randomKeyGenerator'.
  generateUnlockKeys :: SQRLClient clnt m (ServerUnlockKey, VerifyUnlockKey)
  -- | 
  -- | Default 'SQRLClientData' to send to server.
  sqrlClientDataDefault :: SQRLClient clnt m SQRLClientData
  sqrlClientDataDefault = do
    s <- getClientState
    return SQRLClientData
      { clientVersion       = sqrlVersion s
      , clientCommand       = QUERY
      , clientOptions       = Nothing
      , clientAskResponse   = Nothing
      , clientRefererURL    = Nothing
      , clientIdentity      = error "sqrlClientDefaultData: clientIdentity: default clientdata contins no identity."
      , clientPreviousID    = Nothing
      , clientServerUnlock  = Nothing
      , clientVerifyUnlock  = Nothing
      }


-- | Genearates a 'RandomLockKey' from the 'SystemRandom' source.
randomKeyGenerator' :: (MonadIO io, Functor io) => io RandomLockKey
randomKeyGenerator' = (mkDomainKey . fst . throwLeft . genBytes 32) <$> liftIO (newGenIO :: IO SystemRandom)

-- | 
generateUnlockKeys_ :: SQRLClientM clnt m => SQRLClient clnt m PrivateLockKey -> SQRLClient clnt m (ServerUnlockKey, VerifyUnlockKey)
generateUnlockKeys_ f = randomKeyGenerator >>= \x -> f >>= \y -> SQRLClient $ \s -> return (s, (generatePublic x, mkVerifyUnlockKey x y))
{-
generateUnlockKeys_ (SQRLClient f) = let SQRLClient g = randomKeyGenerator in SQRLClient $ \s -> do
  (s', x ) <- g s
  (s'', y) <- f s'
  return (s'', (generatePublic x, mkVerifyUnlockKey x y))
-}

-- | The default implementation of signing a 'SQRLClientPost' using the loaded identities. (See 'sqrlSignPost'.)
sqrlSignPost' :: (SQRLClientM clnt m) => SQRLUrl -> SQRLClientPost a -> SQRLClient clnt m (SQRLClientPost a)
sqrlSignPost' url post = do
  (cid, csig) <- sqrlSign url
  (pid, psig) <- (\x -> case x of { Nothing -> (Nothing, Nothing) ; Just (a, b) -> (Just a, Just b) }) <$> sqrlSignPrevious url
  let post' = modifySQRLClientData (\cdata -> cdata { clientIdentity = cid, clientPreviousID = pid }) post
      post_ = sqrlPostAll post'
      signb :: ByteString
      signb = (fromMaybe (error "sqrlSignPost': no server data") . lookup "client") post_ `BS.append` (fromMaybe (error "sqrlSignPost': no client data") . lookup "server") post_
      wrtfl = unsafePerformIO $ BS.writeFile "/tmp/sqrl-last-sign.log" signb
    in seq wrtfl $ return $ modifySQRLSignatures (\sigs -> sigs { signIdentity = csig signb, signPreviousID = (\f -> f signb) <$> psig, signUnlock = Nothing }) post'


-- | The default implementation of signing a blob using the current identity. (See 'sqrlSign'.)
sqrlSign' :: (SQRLClientM clnt io, MonadIO io) => SQRLUrl -> SQRLClient clnt io (IdentityKey, ByteString -> IdentitySignature)
sqrlSign' dom = sqrlClient $ \s -> do
  (s', priv) <- s `runClient'` sqrlIdentityKey dom
  let pub = generatePublic priv in return (s', (pub, signData priv pub))


-- | The default implementation of signing a blob using the previous identity. (See 'sqrlSign'.)
sqrlSignPrevious' :: (SQRLClientM clnt io, MonadIO io) => SQRLUrl -> SQRLClient clnt io (Maybe (IdentityKey, ByteString -> IdentitySignature))
sqrlSignPrevious' dom = sqrlClient $ \s -> do
  (s', privm) <- s `runClient'` sqrlIdentityKeyPrevious dom
  let keys = (\priv -> (priv, generatePublic priv)) <$> privm
   in return (s', (\(priv, pub) -> (pub, signData priv pub)) <$> keys)

class (PrivateKey pk, DomainKey dk) => DeriveDomainKey pk dk | pk -> dk where
  deriveDomainKey :: SQRLUrl -> pk -> dk
  deriveDomainKey dom imk = mkDomainKey $ sha256hmac (privateKey imk) (TE.encodeUtf8 $ sqrlUrlOrigin dom)

instance DeriveDomainKey PrivateLockKey DomainLockKey
instance DeriveDomainKey PrivateMasterKey DomainIdentityKey
instance DeriveDomainKey PrivateUnlockKey DomainIdentityKey where
  deriveDomainKey dom imk = deriveDomainKey dom (mkPrivateKey (enHash $ privateKey imk) :: PrivateMasterKey)



-- | Create a hash of the bytestring.
sha256hmac :: ByteString -> ByteString -> ByteString
sha256hmac pmk = f . Crypto.Hash.hmac pmk
  where f :: Crypto.Hash.HMAC Crypto.Hash.SHA256 -> ByteString
        f = toBytes

-- | A partial implementation of the lock key of the current identity. (See 'sqrlLockKey'.)
sqrlLockKey_ :: SQRLUrl -> PrivateLockKey -> DomainLockKey
sqrlLockKey_ dom imk = 
  let dh = enHash $ TE.encodeUtf8 $ sqrlUrlOrigin dom  -- TODO: check this entire func
      ipk = enHash $ xorBS (privateLockKey imk) dh
  in DomainLockKey ipk

-- | A client which uses 'SecureStorage' for it's profile management.
class (MonadIO m, SQRLClientM clnt m) => SecureStorageProfile clnt m where
  sspShowProfiles :: Text -> (clnt -> m ()) -> [SQRLProfile] -> m ()
  sspCurrentProfile :: clnt -> Maybe SQRLProfile
  sspCreateProfile :: ((ProfileCreationState -> IO ())    -- ^ a callback which gets notified when the state changes
                       -> IO SQRLEntropy                  -- ^ an external source of entropy (recommended n_bytes > 512), if none is available @const NoEntropy@ should still produce a working result
                       -> Text                            -- ^ name of this profile (may not collide with another)
                       -> Text                            -- ^ password for this profile
                       -> HintLength                      -- ^ the length the password hint should be (see 'HintLength')
                       -> Word16                          -- ^ the time, in minutes, before a hint should be wiped
                       -> PWHashingTime                   -- ^ the amount of time should be spent hashing the password
                       -> ClientFlags                     -- ^ client settings for this profile
                       -> m (Either ProfileCreationError (SQRLProfile, RescueCode))
                      )              -- ^ recommended function for profile creation
                   -> (clnt -> m ()) -- ^ action to run with the new profile
                   -> Text           -- ^ requested profile name (MAY be overriden or confirmed)
                   -> Password       -- ^ requested password (MAY be overriden or confirmed)
                   -> m ()


-- | Default implementation of creating a new profile for a 'SecureStorage' based client.
sqrlCreateProfile' :: (SecureStorageProfile clnt m) => SQRLClient clnt m () -> Text -> Password -> m ()
sqrlCreateProfile' f = sspCreateProfile createProfile (`runClient` f)



-- | Default implementation of choosing a profile for a 'SecureStorage' based client.
sqrlChooseProfile' :: (SecureStorageProfile clnt m, MonadIO m) => Text -> SQRLClient clnt m () -> m ()
sqrlChooseProfile' txt (SQRLClient f) =
  listProfiles >>= sspShowProfiles txt (f >=> return (return ()))

-- | Default implementation of getting the profile name for a 'SecureStorage' based client.
sqrlProfileName' :: (SecureStorageProfile clnt m) => SQRLClient clnt m (Maybe Text)
sqrlProfileName' = sqrlClient' $ \clnt -> return (profileName <$> sspCurrentProfile clnt)


