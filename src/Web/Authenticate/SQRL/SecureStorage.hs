{-# LANGUAGE OverloadedStrings, DefaultSignatures, MultiParamTypeClasses, FunctionalDependencies #-}
module Web.Authenticate.SQRL.SecureStorage where

import Web.Authenticate.SQRL
import Web.Authenticate.SQRL.Client.Types

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.Maybe (catMaybes, fromJust, listToMaybe)
import Data.Time.Clock
import Control.Applicative
import Crypto.Random
import Crypto.Cipher.AES
import qualified Crypto.Hash.SHA256
import qualified Crypto.Scrypt as Scrypt
import qualified Crypto.Ed25519.Exceptions as ED25519
import Control.Exception (catch)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO, MonadIO)
import System.Directory (getModificationTime, getDirectoryContents, getAppUserDataDirectory, doesFileExist, createDirectoryIfMissing)
import System.IO (IOMode(..), withBinaryFile)
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.ByteString.Base64.URL.Lazy as LB64U

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.ByteString (ByteString)
import Data.Byteable
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

getWord64 :: Get Word64
getWord64 = getWord64le
putWord64 :: Word64 -> Put
putWord64 = putWord64le
--getWord32 :: Get Word32
--getWord32 = getWord32le
--putWord32 :: Word32 -> Put
--putWord32 = putWord32le
putWord16 :: Word16 -> Put
putWord16 = putWord16le
getWord16 :: Get Word16
getWord16 = getWord16le

empty256 :: ByteString
empty256 = BS.replicate 32 0
emptySalt :: ByteString
emptySalt = empty256

-- | Create a hash of the bytestring.
sha256 :: ByteString -> ByteString
sha256 = Crypto.Hash.SHA256.hash

-- | A general interface to all blocks containing encrypted data. This allows for the use of 'ssDecrypt' to be applied to all blocks, with the exception of 'BlockOther'.
-- |
-- | Note: If all but 'ssDecrypt' are bound and the decrypted type @r@ is an instance of 'Binary' the default 'ssDecrypt' will do the job.
class SecureStorageEncrypted block r | block -> r where
  -- | Any IV used for encryption and verification.
  ssIV      :: block -> ByteString
  -- | Initial salt for the generation of the 'ProfilePasskey'.
  ssSalt    :: block -> ByteString
  -- | Complexity of each iteration of Scrypt.
  ssLogN    :: block -> LogN
  -- | Iteration count for Scrypt.
  ssIter    :: block -> ScryptIterations
  -- | Any not encrypted values which sould also be verified.
  ssAAD     :: block -> ByteString
  -- | The encrypted content to decrypt.
  ssEncData :: block -> ByteString
  -- | The tag to verify encrypted content to.
  ssVerTag  :: block -> ByteString
  -- | Decrypt this block type and return decrypted data.
  ssDecrypt :: Text -> block -> Maybe r
  default ssDecrypt :: Binary r => Text -> block -> Maybe r
  ssDecrypt pass b = ssDecrypt' (ssVerTag b) (ssIter b) (fromIntegral $ ssLogN b) (ssIV b) (ssSalt b) (ssAAD b) (ssEncData b) pass

ssDecrypt' :: Binary r => ByteString -> ScryptIterations -> Int -> ByteString -> ByteString -> ByteString -> ByteString -> Text -> Maybe r
ssDecrypt' ver iter logn iv salt aad dta pass =
  if toBytes tag /= ver then Nothing
  else case decodeOrFail $ LBS.fromStrict r of
        Left _ -> error "ssDecrypt: tag matched but encrypted data is somehow corrupt."
        Right (_, _, r') -> Just r'
  where pass' = Scrypt.Pass (BS.snoc (TE.encodeUtf8 pass) 0)
        p = fromJust $ Scrypt.scryptParamsLen (fromIntegral logn) 256 1 32
        pssky = thePassKey $ iterscrypt iter p salt pass'
        (r, tag) = decryptGCM (initAES pssky) iv aad dta

-- | Test if two 'ByteString's are the same in time @n@ even if the first byte are diffrent. This thwarts timing attacks unlike the builtin '(==)'.
secureEq :: ByteString -> ByteString -> Bool
secureEq a b = BS.length a == BS.length b &&
               BS.length a == sum (BS.zipWith (\a' b' -> if a' == b' then 1 else 0) a b)

-- | A type representing an master pass key. Destroy as soon as possible.
newtype ProfilePasskey = PassKey { thePassKey :: ByteString }

-- | Iterate the Scrypt function to get a 'ProfilePasskey'.
iterscrypt :: ScryptIterations -> Scrypt.ScryptParams -> ByteString -> Scrypt.Pass -> ProfilePasskey
iterscrypt i p x y = PassKey $ chain (fromIntegral i) xorBS (\a -> Scrypt.getHash $ Scrypt.scrypt p (Scrypt.Salt a) y) x emptySalt

-- | Type 1 - User access password authenticated & encrypted data
--
-- The type 1 'SecureStorage' block supplies the EnScrypt parameters to convert a user-supplied “local access passcode” into a 256-bit symmetric key,
-- and also contains both the plaintext and encrypted data managed by that password.
data SecureStorageBlock1
  = SecureStorageBlock1
    { ss1CryptoIV     :: ByteString        -- ^ init vector for auth/encrypt
    , ss1ScryptSalt   :: ByteString        -- ^ update for password change
    , ss1ScryptLogN   :: LogN              -- ^ memory consumption factor
    , ss1ScryptIter   :: ScryptIterations  -- ^ time consumption factor
    , ss1Flags        :: ClientFlags       -- ^ 16 binary flags
    , ss1HintLen      :: HintLength        -- ^ number of chars in hint
    , ss1PwVerifySec  :: PWHashingTime     -- ^ seconds to run PW EnScrypt
    , ss1HintIdle     :: Word16            -- ^ idle minutes before wiping PW
    , ss1PlainExtra   :: ByteString        -- ^ extended binary data not in spec as of yet
    , ss1Encrypted    :: ByteString        -- ^ encrypted master key, lock key, unlock key etc (see 'SecureStorageBlock1Decrypted')
    , ss1VerifyTag    :: ByteString        -- ^ signature to validate no external changes has been made
    }

-- | This is the decrypted data of 'SecureStorageBlock1' and contains decrypted keys and aditional decrypted data.
data SecureStorageBlock1Decrypted
  = SecureStorageBlock1Decrypted
    { identityMasterKey :: PrivateMasterKey        -- ^ decrypted identity master key
    , identityLockKey   :: PrivateLockKey          -- ^ decrypted identity lock key
    , previousUnlockKey :: Maybe PrivateUnlockKey  -- ^ optional identity unlock key for previous identity
    , ss1DecryptedExtra :: ByteString              -- ^ extended encrypted data not in spec as of yet
    }


instance Binary SecureStorageBlock1Decrypted where
  put b = let (PrivateMasterKey pmk) = identityMasterKey b
              (PrivateLockKey   plk) = identityLockKey   b
              puk = case previousUnlockKey b of { Nothing -> empty256 ; Just (PrivateUnlockKey k) -> k }
          in putByteString pmk *> putByteString plk *> putByteString puk *> putByteString (ss1DecryptedExtra b)
  get = SecureStorageBlock1Decrypted <$> (PrivateMasterKey <$> getByteString 32) <*> (PrivateLockKey <$> getByteString 32)
                                     <*> ((\t -> if t == empty256 then Nothing else Just (PrivateUnlockKey t)) <$> getByteString 32)
                                     <*> (LBS.toStrict <$> getRemainingLazyByteString)


-- | 'ssDecrypt' should be used to decrypt a 'SecureStorageBlock1' from a passphrase.
instance SecureStorageEncrypted SecureStorageBlock1 SecureStorageBlock1Decrypted where
  ssIV = ss1CryptoIV
  ssSalt = ss1ScryptSalt
  ssLogN = ss1ScryptLogN
  ssIter = ss1ScryptIter
  ssAAD x = runGet (lookAhead (skip 32 *> getWord16) >>= getByteString . fromIntegral) (encode x)
  ssEncData = ss1Encrypted
  ssVerTag = ss1VerifyTag


-- | Type 2 - Rescue code encrypted data
--
-- The type 2 'SecureStorage' block supplies the EnScrypt parameters to convert a user-supplied “emergency rescue code” into a 256-bit symmetric key
-- for use in decrypting the block's embedded encrypted emergency rescue code.
data SecureStorageBlock2
  = SecureStorageBlock2
    { ss2ScryptSalt   :: ByteString        -- ^ update for password change
    , ss2ScryptLogN   :: LogN              -- ^ memory consumption factor
    , ss2ScryptIter   :: ScryptIterations  -- ^ time consumption factor
    , ss2Encrypted    :: ByteString        -- ^ encrypted emergency rescue code and any extended encrypted data not in spec as of yet (see 'SecureStorageBlock2Decrypted')
    , ss2VerifyTag    :: ByteString        -- ^ signature to validate no external changes has been made
    }

-- | This is the decrypted data of 'SecureStorageBlock2' and contains an emergency rescue code to transfer an identity.
data SecureStorageBlock2Decrypted
  = SecureStorageBlock2Decrypted
    { identityUnlockKey   :: PrivateUnlockKey     -- ^ decrypted unlock key
    , ss2DecryptedExtra   :: ByteString           -- ^ extended decrypted data not in spec as of yet
    }


instance Binary SecureStorageBlock2Decrypted where
  put b = let (PrivateUnlockKey erc) = identityUnlockKey b in putByteString erc *> putByteString (ss2DecryptedExtra b)
  get = SecureStorageBlock2Decrypted <$> (PrivateUnlockKey <$> getByteString 32) <*> (LBS.toStrict <$> getRemainingLazyByteString)

-- | 'ssDecrypt' should be used to decrypt a 'SecureStorageBlock2' from a passphrase.
instance SecureStorageEncrypted SecureStorageBlock2 SecureStorageBlock2Decrypted where
  ssIV _ = emptyIV
  ssSalt = ss2ScryptSalt
  ssLogN = ss2ScryptLogN
  ssIter = ss2ScryptIter
  ssAAD _ = BS.empty
  ssEncData = ss2Encrypted
  ssVerTag = ss2VerifyTag

emptyIV :: ByteString
emptyIV = BS.replicate 12 0

-- | This two-byte value contains a set of individual single-bit flags corresponding to options offered by SQRL's user-interface.
type ClientFlags = Word16

-- | This one-byte value specifies the number of characters used in password hints. The default is 4 characters. A value of zero disables hinting and causes the SQRL client to prompt its user for their full access password whenever it's required.
type HintLength = Word8

-- | This one-byte value specifies the length of time SQRL's EnScrypt function will run in order to deeply hash the user's password to generate the Identity Master Key's (IMK) symmetric key. SQRL clients are suggested to default this value to five seconds with one second as a minimum. It should not be possible for the user to circumvent at least one second of iterative hashing on any platform.
type PWHashingTime = Word8

type LogN = Word8
type ScryptIterations = Word32

-- | This requests, and gives the SQRL client permission, to briefly check-in with its publisher to see whether any updates to this software have been made available.
clientFlagAutoUpdate :: ClientFlags
clientFlagAutoUpdate = 0x0001

-- | Where a SQRL client is loaded with multiple identities, this prevents the client from assuming any “current user” and
-- causes it to prompt its operator for which identity should be used for every authentication.
-- This can be useful when multiple users share a computer to keep any user from inadvertently attempting to use another user's identity.
clientFlagNoCurrentProfile :: ClientFlags
clientFlagNoCurrentProfile = 0x0002

-- | This adds the @option=sqrlonly@ string to every client transaction. When this option string is present in any properly signed client transaction,
-- this requests the server to set a flag in the user account that will cause the web server to subsequently disable all traditional
-- non-SQRL account logon authentication such as username and password.
clientFlagSQRLOnly :: ClientFlags
clientFlagSQRLOnly = 0x0004

-- | This adds the @option=hardlock@ string to every client transaction. When this option string is present in any properly signed client transaction,
-- this requests the server to set a flag in the user account that will cause the web server to subsequently disable all “out of band” (non-SQRL)
-- account identity recovery options such as “what was your favorite pet's name.”
clientFlagHardLock :: ClientFlags
clientFlagHardLock = 0x0008

-- | When set, this bit instructs the SQRL client to notify its user when the web server indicates that an IP address mismatch exists between the entity
-- that requested the initial logon web page containing the SQRL link URL (and probably encoded into the SQRL link URL's “nut”) and the IP address
-- from which the SQRL client's query was received for this reply.
clientFlagWarnMITM :: ClientFlags
clientFlagWarnMITM = 0x0010

-- | When set, this bit instructs the SQRL client to wash any existing local password and hint data from RAM upon notification that the system
-- is going to sleep in any way such that it cannot be used. This would include sleeping, hibernating, screen blanking, etc.
clientFlagClearOnBlack :: ClientFlags
clientFlagClearOnBlack = 0x0020

-- | When set, this bit instructs the SQRL client to wash any existing local password and hint data from RAM upon notification that the current user is being switched.
--
-- Notice: This could be interpreted as refering to the SQRL profile as in 'clientFlagNoCurrentProfile', but in actuality the "user" above is the user controlled by the OS.
-- I could see it being used either way, though.
clientFlagClearOnUserSwitch :: ClientFlags
clientFlagClearOnUserSwitch = 0x0040

-- | When set, this bit instructs the SQRL client to wash any existing local password and hint data from RAM when the system has been user-idle (no mouse or keyboard activity)
-- for the number of minutes specified by the two-byte idle timeout.
--
-- Notice: The idle time in 'SecureStorageBlock1' is in minutes, when time=0 then no hint is allowed. It is quite clear that this is idle system-wide and not only in usage of SQRL.
-- But since the idle time is allowed to be more than a month;
-- a developer could see this as clearing the hint after being idle in the sense of no SQRL authentications for the specified amounts of minutes if there is no reliable way to detect other activity.
clientFlagClearOnIdle :: ClientFlags
clientFlagClearOnIdle = 0x0080

-- | The default configuration of active flags.
--
-- > def = 'clientFlagAutoUpdate' | 'clientFlagWarnMITM' | 'clientFlagClearOnBlack' | 'clientFlagClearOnUserSwitch' | 'clientFlagClearOnIdle'
clientFlagsDefault :: ClientFlags
clientFlagsDefault = 0x00F1



instance Binary SecureStorageBlock1 where
  get = do blocklen <- getWord16
           if blocklen < 157 then fail "Block too small"
             else do blockt <- getWord16
                     if blockt /= 1 then fail $ "Block type mismatch expected 1 got " ++ show blockt
                       else do ptlen <- getWord16
                               if ptlen < 45 then fail "Inner block to small"
                                 else if ptlen + 112 > blocklen then fail "Inner block to large to fit outer block"
                                      else SecureStorageBlock1
                                           <$> getByteString 12 <*> getByteString 16 <*> getWord8 <*> getWord32                  -- IV and scrypt params
                                           <*> getWord16 <*> getWord8 <*> getWord8 <*> getWord16                                 -- client and hashing settings
                                           <*> getByteString (fromIntegral ptlen - 45)                                           -- additional plain text
                                           <*> getByteString (fromIntegral $ blocklen - ptlen - 16)                              -- all encrypted data
                                           <*> getByteString 16                                                                  -- auth tag
  put b = putWord16 (fromIntegral $ 61 + BS.length (ss1PlainExtra b) + BS.length (ss1Encrypted b)) *> putWord16 1 
       *> putWord16 (fromIntegral $ 45 + BS.length (ss1PlainExtra b))
       *> putByteString (ss1CryptoIV b) *> putByteString (ss1ScryptSalt b)
       *> putWord8 (ss1ScryptLogN b) *> putWord32 (ss1ScryptIter b)
       *> putWord16 (ss1Flags b) *> putWord8 (ss1HintLen b) *> putWord8 (ss1PwVerifySec b) *> putWord16 (ss1HintIdle b)
       *> putByteString (ss1PlainExtra b)
       *> putByteString (ss1Encrypted b)
       *> putByteString (ss1VerifyTag b)


instance Binary SecureStorageBlock2 where
  get = do blocklen <- getWord16
           if blocklen < 73 then fail "Block too small"
             else do blockt <- getWord16
                     if blockt /= 2 then fail $ "Block type mismatch expected 2 got " ++ show blockt
                       else SecureStorageBlock2
                            <$> getByteString 16 <*> getWord8 <*> getWord32       -- scrypt params
                            <*> getByteString (fromIntegral blocklen - 41)        -- encrypted key and any additional encrypted data
                            <*> getByteString 16                                  -- auth tag
  put b = putWord16 (41 + fromIntegral (BS.length (ss2Encrypted b))) *> putWord16 2
       *> putByteString (ss2ScryptSalt b)
       *> putWord8 (ss2ScryptLogN b) *> putWord32 (ss2ScryptIter b)
       *> putByteString (ss2Encrypted b)
       *> putByteString (ss2VerifyTag b)


-- | A collection of related data connected to a specific SQRL profile.
data SecureStorageBlock
  = Block00001 SecureStorageBlock1     -- ^ The most basic of storage blocks. Contains information about master key and encryption settings.
  | Block00002 SecureStorageBlock2     -- ^ Encrypted rescue code.
  | BlockOther Int LBS.ByteString      -- ^ Any other block not supported by the specification at the time of writing, or chosen not to implement. Pull requests are welcome.

-- | A secure storage for a SQRL profile. Contains encrypted keys and SQRL settings.
data SecureStorage = SecureStorage Bool String [SecureStorageBlock]

-- | Get the whole block as a lazy 'LBS.ByteString'.
secureStorageData :: SecureStorageBlock -> LBS.ByteString
secureStorageData (Block00001 b) = encode b
secureStorageData (Block00002 b) = encode b
secureStorageData (BlockOther n bs) = LBS.append (runPut (putWord16 (4 + fromIntegral (LBS.length bs)) *> putWord16 (fromIntegral n))) bs

-- | Get a structured version of the data contained by the block of type 1.
secureStorageData1 :: SecureStorage -> Maybe SecureStorageBlock1
secureStorageData1 (SecureStorage _ _ ss) = case listToMaybe $ filter ((==) 1 . secureStorageType) ss of
  Just (Block00001 b) -> Just b
  _ -> Nothing

-- | Get a structured version of the data contained by the block of type 2.
secureStorageData2 :: SecureStorage -> Maybe SecureStorageBlock2
secureStorageData2 (SecureStorage _ _ ss) = case listToMaybe $ filter ((==) 2 . secureStorageType) ss of
  Just (Block00002 b) -> Just b
  _ -> Nothing

-- | Get the numeric type identifier for the 'SecureStorageBlock'.
secureStorageType :: SecureStorageBlock -> Int
secureStorageType (Block00001 _)   = 1
secureStorageType (Block00002 _)   = 2
secureStorageType (BlockOther n _) = n

-- | Get something specific out of the 'SecureStorageBlock'. Accepts first block of each type.
secureStorageBlock :: Int -> SecureStorage -> Get a -> Maybe a
secureStorageBlock bt (SecureStorage _ _ ss) f = case listToMaybe $ filter ((==) bt . secureStorageType) ss of
  Nothing -> Nothing
  Just sb -> case runGetOrFail f $ secureStorageData sb of
    Left _ -> Nothing
    Right (_, _, r) -> Just r

-- | Open a 'SecureStorage' contained within a 'LBS.ByteString'.
openSecureStorage' :: String -> LBS.ByteString -> Either String SecureStorage
openSecureStorage' fn bs =
  let (hdr, bs') = LBS.splitAt 8 bs
      bs'' | hdr == "sqrldata" = Right bs'
           | hdr == "SQRLDATA" = LB64U.decode bs'
           | otherwise         = Left "Header mismatch"
  in bs'' >>= \bs_ -> case runGetOrFail (oss []) bs_ of
                       Left (_, pos, err) -> Left $ err ++ " (at position " ++ show pos ++ ")"
                       Right (_, _, rslt) -> let slt = reverse rslt in seq slt $ Right $ SecureStorage False fn slt
  where oss :: [SecureStorageBlock] -> Get [SecureStorageBlock]
        oss p = isEmpty >>= \e -> if e then return p else do
          (l, t) <- (,) <$> getWord16 <*> getWord16
          r <- case t of
           1 -> Block00001 <$> get
           2 -> Block00002 <$> get
           _ -> BlockOther (fromIntegral t) <$> getLazyByteString (fromIntegral l - 32)
          let r' = r : p in seq r' $ oss r'

-- | Open a 'SecureStorage' contained within a file.
openSecureStorage :: FilePath -> IO (Either String SecureStorage)
openSecureStorage fp = withBinaryFile fp ReadMode (fmap (openSecureStorage' fp) . LBS.hGetContents)

-- | Turn a 'SecureStorage' into a lazy 'LBS.ByteString'.
saveSecureStorage' :: SecureStorage -> LBS.ByteString
saveSecureStorage' (SecureStorage _ _ ss) = runPut $ putByteString "sqrldata" *> mapM_ sss ss
  where sss :: SecureStorageBlock -> Put
        sss x = case x of
          Block00001 x'  -> put x'
          Block00002 x'  -> put x'
          BlockOther i b -> putWord16 (fromIntegral $ LBS.length b + 32) >> putWord16 (fromIntegral i) >> putLazyByteString b

-- | Saves any changes made to the SecureStorage.
saveSecureStorage :: SecureStorage -> IO ()
saveSecureStorage ss@(SecureStorage True fp _) = LBS.writeFile fp $ saveSecureStorage' ss
saveSecureStorage _ = return ()

-- | Creates an in memory copy of the 'SecureStorage'. This may then be changed and/or saved without affecting the previous storage.
--
-- > -- make a copy of the storage
-- > openSecureStorage "original.ssss" >>= saveSecureStorage . copySecureStorage "copy.ssss" . either (\err -> error err) id
copySecureStorage :: FilePath -> SecureStorage -> SecureStorage
copySecureStorage fp (SecureStorage _ _ ss) = SecureStorage True fp ss


data SQRLProfile
  = SQRLProfile
    { profileName          :: Text
    , profileUsed          :: Maybe UTCTime
    , profileSecureStorage :: IO (Either String SecureStorage)
    }

-- | The separator to use to separate directories in paths.
dirSep :: String
dirSep = "/"

-- | List all profiles contained within a file system directory. It's recommended to use 'listProfiles' unless there is a good reason for not using the default directory.
listProfilesInDir :: FilePath -> IO [SQRLProfile]
listProfilesInDir dir = do
  dd <- map (init . dropWhileEnd ('.'/=))  <$> filter (isSuffixOf ".ssss") <$> getDirectoryContents dir
  catMaybes <$> mapM openProfile dd
  where openProfile d' = case (if all (\x -> x > ' ' && x < 'z') d' then B64U.decode (BS.pack $ map (fromIntegral . fromEnum) d') else Left undefined) of
          Left _ -> return Nothing
          Right bs -> let f = dir ++ "/" ++ d' in do
            t <- catch (fmap Just $ getModificationTime $ f ++ ".time") (const (return Nothing) :: IOError -> IO (Maybe UTCTime))
            return $ Just $ SQRLProfile (TE.decodeUtf8 bs) t $ openSecureStorage (f  ++ ".ssss")
        isSuffixOf suff txt = let sl = length suff
                                  tl = length txt
                              in sl <= tl && drop (tl - sl) txt == suff
        dropWhileEnd _ "" = ""
        dropWhileEnd f (c:cs) = let t = dropWhileEnd f cs in if null t then if f c then "" else [c] else c:t
          

-- | List all profiles which is available in the default profile directory.
listProfiles :: MonadIO io => io [SQRLProfile]
listProfiles = liftIO $ profilesDirectory >>= \d -> createDirectoryIfMissing True d >> listProfilesInDir d

-- | The default file system directory for profiles.
profilesDirectory :: IO FilePath
profilesDirectory = getAppUserDataDirectory $ "sqrl" ++ dirSep ++ "profiles"

-- | ADT representing different types of errors which may occur during profile creation.
data ProfileCreationError
  = ProfileExists
  | RandomError0 GenError
  | RandomError1 GenError
  deriving (Show, Eq)

data ProfileCreationState
  = ProfileCreationFailed ProfileCreationError
  | ProfileCreationSuccess (SQRLProfile, RescueCode)
  | ProfileCreationGeneratingExternal
  | ProfileCreationGeneratingKeys
  | ProfileCreationGeneratingParameters
  | ProfileCreationHashingMasterKey Int
  | ProfileCreationEncryptingUnlock (Int, Int)
  | ProfileCreationEncryptingMaster (Int, Int)

-- | Get a default message describing any 'ProfileCreationState'.
profileCreationMessage :: ProfileCreationState -> String
profileCreationMessage   (ProfileCreationFailed x)                   = "Creation failed: " ++ show x
profileCreationMessage   (ProfileCreationSuccess (x, _))             = "Creation succeded: " ++ show (profileName x)
profileCreationMessage   (ProfileCreationGeneratingExternal)         = "Generating external entropy"
profileCreationMessage   (ProfileCreationGeneratingKeys)             = "Generating keys"
profileCreationMessage   (ProfileCreationGeneratingParameters)       = "Generating parameters"
profileCreationMessage p@(ProfileCreationHashingMasterKey _)         = "Hashing master key - " ++ show (profileCreationInternalPercentage p) ++ "%"
profileCreationMessage p@(ProfileCreationEncryptingUnlock _)         = "Encrypting unlock key - " ++ show (profileCreationInternalPercentage p) ++ "%"
profileCreationMessage p@(ProfileCreationEncryptingMaster _)         = "Encrypting master key - " ++ show (profileCreationInternalPercentage p) ++ "%"


-- | Get an approximate internal percentage (0 just begun - 100 complete) of the completion for the current state.
profileCreationInternalPercentage :: ProfileCreationState -> Int
profileCreationInternalPercentage (ProfileCreationFailed _) = 0
profileCreationInternalPercentage (ProfileCreationSuccess _) = 100
profileCreationInternalPercentage (ProfileCreationGeneratingExternal) = 0
profileCreationInternalPercentage (ProfileCreationGeneratingKeys) = 0
profileCreationInternalPercentage (ProfileCreationGeneratingParameters) = 0
profileCreationInternalPercentage (ProfileCreationHashingMasterKey i) = truncate (fromIntegral i / (16 :: Double))
profileCreationInternalPercentage (ProfileCreationEncryptingUnlock (i,_)) = i
profileCreationInternalPercentage (ProfileCreationEncryptingMaster (i,_)) = i

-- | Get an approximate percentage for the current state. (A failed state returns @-1@.)
profileCreationPercentage :: ProfileCreationState -> Int
profileCreationPercentage (ProfileCreationFailed _) = -1
profileCreationPercentage (ProfileCreationSuccess _) = 100
profileCreationPercentage (ProfileCreationGeneratingExternal) = 0
profileCreationPercentage (ProfileCreationGeneratingKeys) = 0
profileCreationPercentage (ProfileCreationGeneratingParameters) = 12
profileCreationPercentage (ProfileCreationHashingMasterKey i) = 17 + (i `shiftR` 2)
profileCreationPercentage (ProfileCreationEncryptingUnlock (i,_)) = 25 + (i `shiftR` 2)
profileCreationPercentage (ProfileCreationEncryptingMaster (i,_)) = 75 + (i `div` 5)

-- | Hash a password for approximatly an amount of time (in seconds). Time varies depending on device.
enScryptForSecs :: ((Int, Int) -> IO ())    -- ^ progress callback which will be called at most once every second @(percentage done, seconds left)@
              -> Int                        -- ^ the amount of seconds to iterate hashing
              -> LogN                       -- ^ the 'LogN' to be used in the hashing
              -> ByteString                 -- ^ salt to be used
              -> Text                       -- ^ the password to be hashed
              -> IO (ByteString, ScryptIterations)
enScryptForSecs f time logn salt pass = do
  now <- getCurrentTime
  let r = Scrypt.getHash $ Scrypt.scrypt p (Scrypt.Salt salt) pass' in iterscrypt' now (fromIntegral time `addUTCTime` now) r r 0 now
  where pass' = Scrypt.Pass $ TE.encodeUtf8 pass
        p = fromJust $ Scrypt.scryptParamsLen (fromIntegral logn) 256 1 32
        iterscrypt' :: UTCTime -> UTCTime -> ByteString -> ByteString -> ScryptIterations -> UTCTime -> IO (ByteString, ScryptIterations)
        iterscrypt' startTime targetTime salt' passon iter ltime =
          let r = Scrypt.getHash $ Scrypt.scrypt p (Scrypt.Salt salt') pass'
              r' = xorBS passon r
              iter' = iter + 1
              spant = truncate $ targetTime `diffUTCTime` startTime 
              update :: UTCTime -> IO UTCTime
              update t = when (t /= ltime) (f (truncate (t `diffUTCTime` startTime) `div` spant, truncate $ targetTime `diffUTCTime` t)) >> return t
              next :: UTCTime -> IO (ByteString, ScryptIterations)
              next t = if t >= targetTime then return (r', iter') else iterscrypt' startTime targetTime r r' iter' t
          in seq iter' ((if iter' .&. 3 == 0 then return ltime else getCurrentTime >>= update) >>= next)



createProfileInDir :: (ProfileCreationState -> IO ()) -- ^ a callback which gets notified when the state changes
                   -> IO [ByteString]                 -- ^ an external source of entropy (recommended minimum list length of 20 and bytestring length of 32), if none is available @return []@ should still generate an acceptable result.
                   -> Text                            -- ^ name of this profile (may not collide with another)
                   -> Text                            -- ^ password for this profile
                   -> HintLength                      -- ^ the length the password hint should be (see 'HintLength')
                   -> Word16                          -- ^ the time, in minutes, before a hint should be wiped
                   -> PWHashingTime                   -- ^ the amount of time should be spent hashing the password
                   -> ClientFlags                     -- ^ client settings for this profile
                   -> FilePath                        -- ^ the directory which contains the profile
                   -> IO (Either ProfileCreationError (SQRLProfile, RescueCode))
createProfileInDir callback extent name pass hintl hintt time flags dir =
  let f = (++) (dir ++ dirSep) $ map (toEnum . fromIntegral) $ BS.unpack $ B64U.encode $ TE.encodeUtf8 name
  in doesFileExist f >>= \fx -> if fx then return $ Left ProfileExists else (genKeys <$> newGenIO <*> extent) >>= \ekeys -> case ekeys of
      Left err -> return $ Left $ RandomError0 err
      Right (lockKey, unlockKey, rcode) -> (genEncParams <$> newGenIO) >>= \eencp -> case eencp of
        Left err -> return $ Left $ RandomError1 err
        Right (unlockKeySalt, unlockKeyLogN, unlockKeyTime, idKeyIV, idKeySalt, idKeyLogN) -> do
          (idKeyPass, idKeyIter) <- enScryptForSecs (callback . ProfileCreationEncryptingUnlock) (fromIntegral time) idKeyLogN idKeySalt pass
          (unlockKeyPass, unlockKeyIter) <- enScryptForSecs (callback . ProfileCreationEncryptingMaster) (fromIntegral unlockKeyTime) unlockKeyLogN emptySalt $ rescueCode rcode
          let idKey = PrivateMasterKey $ enHash $ privateUnlockKey unlockKey
              (block1enc, idKeyTag) = encryptGCM (initAES idKeyPass) idKeyIV (ssAAD block1) $ BS.concat [ privateMasterKey idKey, privateLockKey lockKey, empty256 ]
              (block2enc, unlockKeyTag) = encryptGCM (initAES unlockKeyPass) emptyIV (ssAAD block2) $ privateUnlockKey unlockKey
              block1 = SecureStorageBlock1
               { ss1CryptoIV     = idKeyIV
               , ss1ScryptSalt   = idKeySalt
               , ss1ScryptLogN   = idKeyLogN
               , ss1ScryptIter   = idKeyIter
               , ss1Flags        = flags
               , ss1HintLen      = hintl
               , ss1PwVerifySec  = time
               , ss1HintIdle     = hintt
               , ss1PlainExtra   = BS.empty
               , ss1Encrypted    = block1enc
               , ss1VerifyTag    = toBytes idKeyTag
               }
              block2 = SecureStorageBlock2
               { ss2ScryptSalt   = unlockKeySalt
               , ss2ScryptIter   = unlockKeyIter
               , ss2ScryptLogN   = unlockKeyLogN
               , ss2Encrypted    = block2enc
               , ss2VerifyTag    = toBytes unlockKeyTag
               }
              f' = f ++ ".ssss"
              ss = SecureStorage True f' [Block00001 block1, Block00002 block2]
          saveSecureStorage ss
          return $ Right (SQRLProfile { profileName = name, profileUsed = Nothing, profileSecureStorage = openSecureStorage f' }, rcode)
  where genKeys :: SystemRandom -> [ByteString] -> Either GenError (PrivateLockKey, PrivateUnlockKey, RescueCode)
        genKeys g ntrpy = (genKeys' ntrpy . fst) <$> genBytes 128 g
        genKeys' ntrpy genbytes =
           let (shastate, chnks) = takeAtLeast10ButLeave10IfPossible (Crypto.Hash.SHA256.updates $ Crypto.Hash.SHA256.update Crypto.Hash.SHA256.init $ BS.take 96 genbytes) ntrpy
               unlockKey = Crypto.Hash.SHA256.finalize shastate
               lockKey = ED25519.exportPublic $ ED25519.generatePublic $ fromJust $ ED25519.importPrivate unlockKey
               rcode = Crypto.Hash.SHA256.finalize $ Crypto.Hash.SHA256.updates shastate $ BS.drop 32 genbytes : chnks
           in (PrivateLockKey lockKey, PrivateUnlockKey unlockKey, genRcode rcode)
        takeAtLeast10ButLeave10IfPossible f x =
          let (x0, x') = splitAt 10 x
              (x1, x2) = splitAt 10 x'
          in (f (x0 ++ x2), x1)
        genEncParams :: SystemRandom -> Either GenError (ByteString, LogN, Int, ByteString, ByteString, LogN)
        genEncParams g = (genEncParams' . fst) <$> genBytes (16 + 1 + 1 + 12 + 16 + 1) g
        genEncParams' :: ByteString -> (ByteString, LogN, Int, ByteString, ByteString, LogN)
        genEncParams' bs =
          let unlockKeySalt = BS.take 16 bs
              unlockKeyLogN = (BS.index bs 16 .&. 0x7F) + 0x23
              unlockKeyTime = fromIntegral (complement (BS.index bs 17 .&. 0x7F)) `shiftL` 2
              idKeyIV = BS.take 12 $ BS.drop 18 bs
              idKeySalt = BS.take 16 $ BS.drop 30 bs
              idKeyLogN = (BS.index bs 46 .&. 63) + 0x23
          in (unlockKeySalt, unlockKeyLogN, unlockKeyTime, idKeyIV, idKeySalt, idKeyLogN)
        bsToNatural :: ByteString -> Integer
        bsToNatural = BS.foldl (\i w -> (i `shiftL` 8) + fromIntegral w) 0
        genRcode :: ByteString -> RescueCode
        genRcode = RescueCode . T.pack . take 24 . genRcode' . bsToNatural
        genRcode' i = let (i', r) = i `quotRem` 10 in head (show r) : genRcode' i'

xorBS :: ByteString -> ByteString -> ByteString
xorBS a = BS.pack . BS.zipWith xor a

enHash :: ByteString -> ByteString
enHash inp = chain 16 xorBS sha256 inp empty256

-- | Do chained operations. @chain i f h a b@ means derive a new @a' = h a@ which then gets used to derive a new @b' = f a' b@. The new @a'@ and @b'@ are used recursivly for a total of @i@ times before the last @b'@ is returned.
chain :: Int -> (a -> b -> b) -> (a -> a) -> a -> b -> b
chain 0 _ _ _ b = b
chain i f h a b = let { i' = i - 1 ; a' = h a ; b' = f a' b} in i' `seq` (b' `seq` chain i' f h a' b')

-- | Creates a new SQRL profile. This includes generating keys, a 'RescueCode', hashing passwords and creating a 'SecureStorage'.
--
-- The resulting profile is returned if no error occured during the creation.
createProfile :: (MonadIO io)
              => (ProfileCreationState -> IO ()) -- ^ a callback which gets notified when the state changes
              -> IO [ByteString]                 -- ^ an external source of entropy (recommended minimum list length of 20 and bytestring length of 32), if none is available @return []@ should still generate an acceptable result.
              -> Text                            -- ^ name of this profile (may not collide with another)
              -> Text                            -- ^ password for this profile
              -> HintLength                      -- ^ the length the password hint should be (see 'HintLength')
              -> Word16                          -- ^ the time, in minutes, before a hint should be wiped
              -> PWHashingTime                   -- ^ the amount of time should be spent hashing the password
              -> ClientFlags                     -- ^ client settings for this profile
              -> io (Either ProfileCreationError (SQRLProfile, RescueCode))
createProfile callback extent name pass hintl hintt time flags = liftIO (profilesDirectory >>= createProfileInDir callback extent name pass hintl hintt time flags)
