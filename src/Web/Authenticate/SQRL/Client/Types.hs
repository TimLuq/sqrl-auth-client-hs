{-# LANGUAGE MultiParamTypeClasses, FunctionalDependencies #-}
module Web.Authenticate.SQRL.Client.Types where

import Web.Authenticate.SQRL.Types

import Data.ByteString (ByteString)
import Data.Text (Text)
import Control.Exception (SomeException)
import Data.Maybe (fromMaybe)

import qualified Crypto.Ed25519.Exceptions as ED25519

type FullRealm = Text
type Password = Text

newtype PublicLockKey = PublicLockKey { publicLockKey :: ByteString }

newtype RescueCode         = RescueCode { rescueCode :: Text }
--newtype PrivateIdentityKey = PrivateIdentityKey { privateIdentityKey :: ByteString }
newtype PrivateMasterKey   = PrivateMasterKey   { privateMasterKey   :: ByteString } deriving (Show, Eq)
newtype PrivateUnlockKey   = PrivateUnlockKey   { privateUnlockKey   :: ByteString } deriving (Show, Eq)
newtype PrivateLockKey     = PrivateLockKey     { privateLockKey     :: ByteString } deriving (Show, Eq)

class (PublicKey pub, DomainKey priv, Signature sig) => KeyPair priv pub sig | priv -> pub sig where
  -- | Generates a public key from a 'DomainKey'.
  generatePublic :: priv -> pub
  generatePublic = mkPublicKey . ED25519.exportPublic . ED25519.generatePublic . fromMaybe (error "KeyPair.generatePublic: importPrivate returned Nothing.") . ED25519.importPrivate . domainKey
  signData :: priv -> pub -> ByteString -> sig
  signData priv' pub' bs =
    let ED25519.Sig sig = ED25519.sign bs priv pub
        priv = fromMaybe (error "KeyPair.signData: importPrivate returned Nothing.") $ ED25519.importPrivate $ domainKey priv'
        pub  = fromMaybe (error "KeyPair.signData: importPublic returned Nothing.")  $ ED25519.importPublic  $ publicKey pub'
    in mkSignature sig
instance KeyPair DomainIdentityKey IdentityKey IdentitySignature

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

newtype DomainLockKey      = DomainLockKey      { domainLockKey      :: ByteString } deriving (Show, Eq)
newtype DomainIdentityKey  = DomainIdentityKey  { domainIdentityKey  :: ByteString } deriving (Show, Eq)


class DomainKey k where
  domainKey :: k -> ByteString
  mkDomainKey :: ByteString -> k

instance DomainKey DomainLockKey where
  domainKey = domainLockKey
  mkDomainKey = DomainLockKey
instance DomainKey DomainIdentityKey where
  domainKey = domainIdentityKey
  mkDomainKey = DomainIdentityKey


data ClientErr
  = ClientErrNone
  | ClientErrLoginAborted
  | ClientErrAskAborted
  | ClientErrAssocAborted
  | ClientErrNoProfile
  | ClientErrWrongPassword
  | ClientErrSecureStorage String
  | ClientErrDecryptionFailed String
  | ClientErrThrown SomeException
  | ClientErrOther String
  deriving (Show)
