{-# LANGUAGE OverloadedStrings #-}
module Web.Authenticate.SQRL.Client where

import Web.Authenticate.SQRL
import Web.Authenticate.SQRL.SecureStorage

import Crypto.Random
import qualified Data.Text as T
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.ByteString.Base64.URL as B64U
import qualified Crypto.Ed25519.Exceptions as ED25519

newtype PrivateKey = PrivKey ByteString
type MasterKey = PrivateKey
type PrivateUnlockKey = PrivateKey


type SQRLClientIO clnt = SQRLClient clnt IO => clnt

newtype SQRLClientM clnt m => SQRLClient clnt m t = SQRLClient (clnt -> m (clnt, t))

instance Functor SQRLClient where
  fmap f (SQRLClient x) = SQRLClient . f . x

instance Monad SQRLClient where
  return x = SQRLClient $ \s -> return (s,x)
  (SQRLClient fx) >>= (SQRLClient fy) = SQRLClient $ \s -> fx s >>= \(s', y) -> fy s' y
  (SQRLClient fx) >> (SQRLCLient fy) = SQRLClient $ \s -> fx s >> \(s', _) -> fy s'

instance Applicative SQRLClient where
  pure x = SQRLClient $ \s -> (s, x)
  (SQRLClient ff) <*> (SQRLClient xf) = SQRLClient $ \s -> ff s >>= \(s', f) -> xf s' >>= \(s'', x) -> return (s'', f x)
  (SQRLClient fx) <*  (SQRLClient fy) = SQRLClient $ \s -> fx s >>= \(s', x) -> fy s' >>= \(s'', _) -> return (s'', x)
  (SQRLClient fx)  *> (SQRLClient fy) = SQRLClient $ \s -> fx s >>= \(s', _) -> fy s' >>= \(s'', y) -> return (s'', y)


-- | Do some action with the client.
sqrlClient :: (clnt -> m (clnt, t)) -> SQRLClient clnt m t
sqrlClient = SQRLClient

-- | Do some action with the client without modifying the state.
--
-- Actions in the IO monad are discouraged unless they are transactional due to risk of the client getting out of sync.
sqrlClient' :: (clnt -> m t) -> SQRLClient clnt m t
sqrlClient' f = SQRLClient $ \clnt -> (clnt, f clnt)

-- | Run some action with a client and return the result.
runClient :: clnt -> SQRLClient clnt m t -> m t
runClient clnt (SQRLClient f) = f clnt >>= snd

-- | Run some action with a client and return both the updated client state as well as the result.
runClient' :: clnt -> SQRLClient clnt m t -> m (clnt, t)
runClient' clnt (SQRLClient f) = f clnt


class Monad m => SQRLClientM clnt m where
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
  sqrlSign :: Domain -> ByteString -> SQRLClient clnt m SQRLSignature
  default sqrlSign :: MonadIO io => Domain -> ByteString -> SQRLClient clnt io SQRLSignature
  sqrlSign = sqrlSign'
  -- | Sign blobs of data for a single domain using the previous identity.
  sqrlSignPrevious :: Domain -> ByteString -> SQRLClient clnt m SQRLSignature
  default sqrlSignPrevious :: MonadIO io => Domain -> ByteString -> SQRLClient clnt io (Maybe SQRLSignature)
  sqrlSignPrevious = sqrlSignPrevious'
  -- | The private key of the current identity for a single domain.
  sqrlIdentityKey :: Domain -> SQRLClient clnt m IdentityPrivateKey
  -- | The private key of the previous identity for a single domain.
  sqrlIdentityKeyPrevious :: Domain -> SQRLClient clnt m (Maybe IdentityPrivateKey)
  -- | The lock key of the current identity for a single domain.
  sqrlLockKey :: Domain -> SQRLClient clnt m LockPrivateKey
  -- | Lets the user choose the profile to use when executing a client session.
  sqrlChooseProfile :: Text                 -- ^ short description why a profile is to be selected
                    -> SQRLClient clnt m a  -- ^ action for the selected profile
                    -> m ()
  default sqrlChooseProfile :: (SecureStorageProfile clnt m) => Text -> SQRLClient clnt m a -> m ()
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
sqrlSign' :: MonadIO io => Domain -> ByteString -> SQRLClient clnt io SQRLSignature
sqrlSign' dom bs = sqrlClient $ \s ->
  let (s', priv') = s `runClient'` sqrlPrivateKey dom
      priv = ED25519.importPrivate priv'
      pub = ED25519.generatePublic priv
      ED25519.Sig sig = ED25519.sign bs priv pub
  in (s', SQRLSignature sig)

-- | A partial implementation of the private key of any identity. (See 'sqrlIdentityKey' and 'sqrlIdentityKeyPrevious'.)
sqrlIdentityKey_ :: Domain -> IdentityMasterKey -> IdentityPrivateKey
sqrlIdentityKey_ dom imk = 
  let dh = enHash dom  -- TODO: check this entire func
      ipk = enHash $ xorBS imk dh
  in IdentityPrivateKey ipk

-- | A partial implementation of the lock key of the current identity. (See 'sqrlLockKey'.)
sqrlLockKey_ :: MonadIO io => Domain -> LockMasterKey -> LockPrivateKey
sqrlLockKey_ dom imk = 
  let dh = enHash dom  -- TODO: check this entire func
      ipk = enHash $ xorBS imk dh
  in LockPrivateKey ipk

-- | A client which uses 'SecureStorage' for it's profile management.
class (MonadIO m, SQRLClientM clnt m) => SecureStorageProfile clnt m where
  sspShowProfiles :: Maybe (Text, clnt -> m ()) -> [SQRLProfile] -> m ()
  sspCurrentProfile :: clnt -> Maybe SQRLProfile
  sspCreateProfile :: ((ProfileCreationState -> IO ())    -- ^ a callback which gets notified when the state changes
                       -> IO ByteString                   -- ^ an external source of entropy (recommended n_bytes in [4,12]), if none is available @const ByteString.empty@ may still be good enough
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
sqrlCreateProfile' f = sspCreateProfile createProfile (flip runClient f)



-- | Default implementation of choosing a profile for a 'SecureStorage' based client.
sqrlChooseProfile' :: (SecureStorageProfile clnt m) => Text -> SQRLClient clnt m a -> m ()
sqrlChooseProfile' txt f =
  listProfiles >>= sspShowProfiles (Just (txt, flip runClient f))

-- | Default implementation of getting the profile name for a 'SecureStorage' based client.
sqrlProfileName' :: (SecureStorageProfile clnt m) => SQRLClient clnt m (Maybe Text)
sqrlProfileName' = sqrlClient' $ \clnt -> return $ (profileName <$> sspCurrentProfile clnt)


