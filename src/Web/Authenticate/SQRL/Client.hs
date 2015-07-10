{-# LANGUAGE OverloadedStrings, DefaultSignatures, MultiParamTypeClasses, FunctionalDependencies #-}
module Web.Authenticate.SQRL.Client where

import Web.Authenticate.SQRL
import Web.Authenticate.SQRL.SecureStorage
import Web.Authenticate.SQRL.Client.Types

import Data.Word (Word16)

--import Crypto.Random
import Data.ByteString (ByteString)
import Data.Byteable
--import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Maybe (fromJust)
--import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
--import qualified Data.ByteString.Base64.URL as B64U
import qualified Crypto.Ed25519.Exceptions as ED25519
import qualified Crypto.Hash
import Control.Applicative
import Control.Monad.IO.Class (MonadIO)

newtype SQRLClient clnt m t = SQRLClient (clnt -> m (clnt, t))
--type SQRLClientIO clnt t = SQRLClient clnt IO t


instance Functor m => Functor (SQRLClient clnt m) where
  fmap f (SQRLClient x) = let f' (s, t) = (s, f t) in SQRLClient $ \s' -> fmap f' (x s')

instance Monad m => Monad (SQRLClient clnt m) where
  return x = SQRLClient $ \s -> return (s,x)
  (SQRLClient fx) >>= ffy = SQRLClient $ \s -> fx s >>= \(s', y) -> let (SQRLClient fy) = ffy y in fy s'
  (SQRLClient fx) >> (SQRLClient fy) = SQRLClient $ \s -> fx s >>= \(s', _) -> fy s'

instance (Functor m, Monad m) => Applicative (SQRLClient clnt m) where
  pure x = SQRLClient $ \s -> return (s, x)
  (SQRLClient ff) <*> (SQRLClient xf) = SQRLClient $ \s -> ff s >>= \(s', f) -> xf s' >>= \(s'', x) -> return (s'', f x)
  (SQRLClient fx) <*  (SQRLClient fy) = SQRLClient $ \s -> fx s >>= \(s', x) -> fy s' >>= \(s'', _) -> return (s'', x)
  (SQRLClient fx)  *> (SQRLClient fy) = SQRLClient $ \s -> fx s >>= \(s', _) -> fy s' >>= \(s'', y) -> return (s'', y)


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
  -- | Sign blobs of data for a single domain using the current identity.
  sqrlSign :: FullRealm -> ByteString -> SQRLClient clnt m IdentitySignature
  default sqrlSign :: MonadIO m => FullRealm -> ByteString -> SQRLClient clnt m IdentitySignature
  sqrlSign = sqrlSign'
  -- | Sign blobs of data for a single domain using the previous identity.
  sqrlSignPrevious :: FullRealm -> ByteString -> SQRLClient clnt m (Maybe IdentitySignature)
  default sqrlSignPrevious :: MonadIO m => FullRealm -> ByteString -> SQRLClient clnt m (Maybe IdentitySignature)
  sqrlSignPrevious = sqrlSignPrevious'
  -- | The private key of the current identity for a single domain.
  sqrlIdentityKey :: FullRealm -> SQRLClient clnt m DomainIdentityKey
  -- | The private key of the previous identity for a single domain.
  sqrlIdentityKeyPrevious :: FullRealm -> SQRLClient clnt m (Maybe DomainIdentityKey)
  -- | The lock key of the current identity for a single domain.
  sqrlLockKey :: FullRealm -> SQRLClient clnt m DomainLockKey
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
  -- | Request deletion of any sensitive data.
  sqrlClearSensitive :: SQRLClient clnt m ()
  -- | Request deletion of any data protected by a simplified hint.
  sqrlClearHint :: SQRLClient clnt m ()






-- | The default implementation of signing a blob using the current identity. (See 'sqrlSign'.)
sqrlSign' :: (SQRLClientM clnt io, MonadIO io) => FullRealm -> ByteString -> SQRLClient clnt io IdentitySignature
sqrlSign' dom bs = sqrlClient $ \s -> do
  (s', priv') <- s `runClient'` sqrlIdentityKey dom
  let priv = fromJust $ ED25519.importPrivate $ domainIdentityKey  priv'
      pub = ED25519.generatePublic priv
      ED25519.Sig sig = ED25519.sign bs priv pub
   in return (s', mkSignature sig)


-- | The default implementation of signing a blob using the previous identity. (See 'sqrlSign'.)
sqrlSignPrevious' :: (SQRLClientM clnt io, MonadIO io) => FullRealm -> ByteString -> SQRLClient clnt io (Maybe IdentitySignature)
sqrlSignPrevious' dom bs = sqrlClient $ \s -> do
  (s', priv') <- s `runClient'` sqrlIdentityKeyPrevious dom
  let priv = fromJust $ ED25519.importPrivate $ domainIdentityKey $ fromJust priv'
      pub = ED25519.generatePublic priv
      ED25519.Sig sig = ED25519.sign bs priv pub
   in return (s', const (mkSignature sig) <$> priv')

class (PrivateKey pk, DomainKey dk) => DeriveDomainKey pk dk | pk -> dk where
  deriveDomainKey :: FullRealm -> pk -> dk
  deriveDomainKey dom imk = mkDomainKey $ sha256hmac (privateKey imk) (TE.encodeUtf8 dom)

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
sqrlLockKey_ :: FullRealm -> PrivateLockKey -> DomainLockKey
sqrlLockKey_ dom imk = 
  let dh = enHash $ TE.encodeUtf8 dom  -- TODO: check this entire func
      ipk = enHash $ xorBS (privateLockKey imk) dh
  in DomainLockKey ipk

-- | A client which uses 'SecureStorage' for it's profile management.
class (MonadIO m, SQRLClientM clnt m) => SecureStorageProfile clnt m where
  sspShowProfiles :: Maybe (Text, clnt -> m ()) -> [SQRLProfile] -> m ()
  sspCurrentProfile :: clnt -> Maybe SQRLProfile
  sspCreateProfile :: ((ProfileCreationState -> IO ())    -- ^ a callback which gets notified when the state changes
                       -> IO [ByteString]                 -- ^ an external source of entropy (recommended n_bytes in [4,12]), if none is available @const ByteString.empty@ may still be good enough
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
  listProfiles >>= sspShowProfiles (Just (txt, \s -> f s >>= return (return ())))

-- | Default implementation of getting the profile name for a 'SecureStorage' based client.
sqrlProfileName' :: (SecureStorageProfile clnt m) => SQRLClient clnt m (Maybe Text)
sqrlProfileName' = sqrlClient' $ \clnt -> return (profileName <$> sspCurrentProfile clnt)


