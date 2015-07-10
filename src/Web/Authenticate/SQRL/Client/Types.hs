module Web.Authenticate.SQRL.Client.Types where


import Data.ByteString (ByteString)
import Data.Text (Text)

type FullRealm = Text
type Password = Text

newtype PublicLockKey = PublicLockKey { publicLockKey :: ByteString }

newtype RescueCode         = RescueCode { rescueCode :: Text }
--newtype PrivateIdentityKey = PrivateIdentityKey { privateIdentityKey :: ByteString }
newtype PrivateMasterKey   = PrivateMasterKey   { privateMasterKey   :: ByteString }
newtype PrivateUnlockKey   = PrivateUnlockKey   { privateUnlockKey   :: ByteString }
newtype PrivateLockKey     = PrivateLockKey     { privateLockKey     :: ByteString }

class PrivateKey k where
  privateKey :: k -> ByteString
  mkPrivateKey :: ByteString -> k

instance PrivateKey PrivateMasterKey where
  privateKey = privateMasterKey
  mkPrivateKey = PrivateMasterKey
instance PrivateKey PrivateUnlockKey where
  privateKey = privateUnlockKey
  mkPrivateKey = PrivateUnlockKey
instance PrivateKey PrivateLockKey where
  privateKey = privateLockKey
  mkPrivateKey = PrivateLockKey

newtype DomainLockKey      = DomainLockKey      { domainLockKey      :: ByteString }
newtype DomainIdentityKey  = DomainIdentityKey  { domainIdentityKey  :: ByteString }


class DomainKey k where
  domainKey :: k -> ByteString
  mkDomainKey :: ByteString -> k

instance DomainKey DomainLockKey where
  domainKey = domainLockKey
  mkDomainKey = DomainLockKey
instance DomainKey DomainIdentityKey where
  domainKey = domainIdentityKey
  mkDomainKey = DomainIdentityKey
