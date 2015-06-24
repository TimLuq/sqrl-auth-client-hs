{-# LANGUAGE OverloadedStrings #-}
module Web.Authenticate.SQRL.SecureStorage where

import Web.Authenticate.SQRL
import Web.Authenticate.SQRL.Client


-- | A general interface to all blocks containing encrypted data. This allows for the use of 'ssDecrypt' to be applied to all blocks, with the exception of 'BlockOther'.
-- |
-- | Note: If all but 'ssDecrypt' are bound and the decrypted type @r@ is an instance of 'Binary' the default 'ssDecrypt' will do the job.
class SecureStorageEncrypted block r where
  -- | Any IV used for encryption and verification.
  ssIV      :: block -> ByteString
  -- | Initial salt for the generation of the 'ProfilePasskey'.
  ssSalt    :: block -> ByteString
  -- | Complexity of each iteration of Scrypt.
  ssLogN    :: block -> Word8
  -- | Iteration count for Scrypt.
  ssIter    :: block -> Word32
  -- | Any not encrypted values which sould also be verified.
  ssAAD     :: block -> ByteString
  -- | The encrypted content to decrypt.
  ssEncData :: block -> ByteString
  -- | The tag to verify encrypted content to.
  ssVerTag  :: block -> ByteString
  -- | Decrypt this block type and return decrypted data.
  ssDecrypt :: Text -> block -> Maybe r
  default ssDecrypt :: Binary r => Text -> block -> Maybe r
  ssDecrypt pass b = ssDecrypt' (ssIter b) (fromIntegral $ ssLogN b) (ssIV b) (ssSalt b) (ssAAD b) (ssEncData b) pass

ssDecrypt' :: Word32 -> Int -> ByteString -> ByteString -> ByteString -> ByteString -> Text -> ProfilePasskey
ssDecrypt' iter logn iv salt aad dta pass =
  if toBytes tag /= ssVerTag b then Nothing
  else case decodeOrFail $ LBS.fromStrict r of
        Left _ -> error "ssDecrypt: tag matched but encrypted data is somehow corrupt."
        Right (_, _, r') -> Just r
  where pass' = Scrypt.Pass (BS.snoc (TE.encodeUtf8 pass) 0)
        pssky = thePassKey $ iterscrypt iter (Scrypt.scryptParamsLen (logn) 256 1 32) salt pass'
        (r, tag) = decryptGCM (initAES pssky) iv aad dta


-- | A type representing an master pass key. Destroy as soon as possible.
newtype ProfilePasskey = PassKey { thePassKey :: ByteString }

-- | Iterate the Scrypt function to get a 'ProfilePasskey'.
iterscrypt :: Word32 -> Scrypt.ScryptParams -> ByteString -> Scrypt.Pass -> ProfilePasskey
iterscrypt 0 _ x _ = PassKey x
iterscrypt i p x y = let r = Scrypt.getHash $ Scrypt.scrypt p (Scrypt.Salt x) y in PassKey $ iterscrypt' (i-1) r
  where iterscrypt' 0 a = a
        iterscrypt' n r = let r' = Scrypt.getHash $ Scrypt.scrypt p (Scrypt.Salt r) y in iterscrypt' (n-1) $ BS.pack $ BS.zipWith xor r r'

-- | Type 1 - User access password authenticated & encrypted data
--
-- The type 1 'SecureStorage' block supplies the EnScrypt parameters to convert a user-supplied “local access passcode” into a 256-bit symmetric key,
-- and also contains both the plaintext and encrypted data managed by that password.
data SecureStorageBlock1
  = SecureStorageBlock1
    { ss1CryptoIV     :: ByteString    -- ^ init vector for auth/encrypt
    , ss1ScryptSalt   :: ByteString    -- ^ update for password change
    , ss1ScryptLogN   :: Word8         -- ^ memory consumption factor
    , ss1ScryptIter   :: Word32        -- ^ time consumption factor
    , ss1Flags        :: ClientFlags   -- ^ 16 binary flags
    , ss1HintLen      :: HintLength    -- ^ number of chars in hint
    , ss1PwVerifySec  :: PWHashingTime -- ^ seconds to run PW EnScrypt
    , ss1HintIdle     :: Word16        -- ^ idle minutes before wiping PW
    , ss1PlainExtra   :: ByteString    -- ^ extended binary data not in spec as of yet
    , ss1Encrypted    :: ByteString    -- ^ encrypted master key, lock key, unlock key etc (see 'SecureStorageBlock1Decrypted')
    , ss1VerifyTag    :: ByteString    -- ^ signature to validate no external changes has been made
    }

-- | This is the decrypted data of 'SecureStorageBlock1' and contains decrypted keys and aditional decrypted data.
data SecureStorageBlock1Decrypted
  = SecureStorageBlock1Decrypted
    { identityMasterKey :: MasterKey   -- ^ decrypted identity master key
    , identityLockKey   :: PrivateKey  -- ^ decrypted identity lock key
    , identityUnlockKey :: UnlockKey   -- ^ optional identity unlock key for previous identity (compare to 'emptyUnlockKey')
    , ss1DecryptedExtra :: ByteString  -- ^ extended encrypted data not in spec as of yet
    }

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
    { ss2ScryptSalt   :: ByteString      -- ^ update for password change
    , ss2ScryptLogN   :: Word8           -- ^ memory consumption factor
    , ss2ScryptIter   :: Word32          -- ^ time consumption factor
    , ss2Encrypted    :: ByteString      -- ^ encrypted emergency rescue code and any extended encrypted data not in spec as of yet (see 'SecreStorageBLock2Decrypted')
    , ss2VerifyTag    :: ByteString      -- ^ signature to validate no external changes has been made
    }

-- | This is the decrypted data of 'SecureStorageBlock2' and contains an emergency rescue code to transfer an identity.
data SecreStorageBlock2Decrypted
  = SecureStorageBlock2Decrypted
    { emergencyRescueCode :: RescueCode    -- ^ decrypted emergency rescue code
    , ss2DecryptedExtra   :: ByteString    -- ^ extended decrypted data not in spec as of yet
    }


instance Binary SecureStorageBlock2Decrypted where
  put b = let (RescueCode erc) = emergencyRescueCode b in putByteString erc *> putByteString (ss2DecryptedExtra b)
  get = SecureStorageBlock2Decrypted <$> getByteString 32 <*> (LBS.toStrict <$> getRemainingLazyByteString)

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
clientFlagSQRLOnly :: ClientFlags
clientFlagSQRLOnly = 0x0008

-- | When set, this bit instructs the SQRL client to notify its user when the web server indicates that an IP address mismatch exists between the entity
-- that requested the initial logon web page containing the SQRL link URL (and probably encoded into the SQRL link URL's “nut”) and the IP address
-- from which the SQRL client's query was received for this reply.
clientFlagWarnMITM :: ClientFlags
clientFlagWarnMITM = 0x0010

-- | When set, this bit instructs the SQRL client to wash any existing local password and hint data from RAM upon notification that the system
-- is going to sleep in any way such that it cannot be used. This would include sleeping, hibernating, screen blanking, etc.
clientFlagDiscardOnBlack :: ClientFlags
clientFlagDiscardOnBlack = 0x0020

-- | When set, this bit instructs the SQRL client to wash any existing local password and hint data from RAM upon notification that the current user is being switched.
--
-- Notice: This could be interpreted as refering to the SQRL profile as in 'clientFlagNoCurrentProfile', but in actuality the "user" above is the user controlled by the OS.
-- I could see it being used either way, though.
clientFlagDiscardOnUserSwitch :: ClientFlags
clientFlagDiscardOnUserSwitch = 0x0040

-- | When set, this bit instructs the SQRL client to wash any existing local password and hint data from RAM when the system has been user-idle (no mouse or keyboard activity)
-- for the number of minutes specified by the two-byte idle timeout.
--
-- Notice: The idle time in 'SecureStorageBlock1' is in minutes, when time=0 then no hint is allowed. It is quite clear that this is idle system-wide and not only in usage of SQRL.
-- But since the idle time is allowed to be more than a month;
-- a developer could see this as clearing the hint after being idle in the sense of no SQRL authentications for the specified amounts of minutes if there is no reliable way to detect other activity.
clientFlagDiscardOnIdle :: ClientFlags
clientFlagDiscardOnIdle = 0x0080

-- | The default configuration of active flags.
--
-- > def = 'clientFlagAutoUpdate' | 'clientFlagWarnMITM' | 'clientFlagDiscardOnBlack' | 'clientFlagDiscardOnUserSwitch' | 'clientFlagDiscardOnIdle'
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
                                           <$> getByteString 12 <*> getByteString 16 <*> getWord8 <*> getWord32       -- IV and scrypt params
                                           <*> getWord16 <*> getWord8 <*> getWord16 <*> getByteString (ptlen - 45)    -- additional plain text
                                           <*> getByteString 32 <*> getByteString 32 <*> getByteString 32             -- encrypted keys
                                           <*> getByteString (blocklen - ptlen - 16)                                  -- all encrypted data
                                           <*> getByteString 16                                                       -- auth tag
  put b =  putWord16 (61 + BS.length (ss1PlainExtra b) + BS.length (ss1Encrypted b)) <*> putWord16 1 
       <*> putWord16 (45 + BS.length (ss1PlainExtra b))
       <*> putByteString (ss1CryptoIV b) <*> putByteString (ss1ScryptSalt b)
       <*> putWord8 (ss1ScryptLogN b) <*> putWord32 (ss1ScryptIter b)
       <*> putWord16 (ss1Flags b) <*> putWord8 (ss1HintLen b) <*> putWord16 (ss1HintIdle b)
       <*> putByteString (ss1PlainExtra b)
       <*> putByteString (ss1Encrypted b)
       <*> putByteString (ss1VerifyTag b)


instance Binary SecureStorageBlock2 where
  get = do blocklen <- getWord16
           if blocklen < 73 then fail "Block too small"
             else do blockt <- getWord16
                     if blockt /= 2 then fail $ "Block type mismatch expected 2 got " ++ show blockt
                       else SecureStorageBlock2
                            <$> getByteString 16 <*> getWord8 <*> getWord32       -- scrypt params
                            <*> getByteString (blocklen - 41)                     -- encrypted key and any additional encrypted data
                            <*> getByteString 16                                  -- auth tag
  put b =  putWord16 (41 + BS.length (ss2Encrypted b)) <*> putWord16 2
       <*> putByteString (ss2ScryptSalt b)
       <*> putWord8 (ss2ScryptLogN b) <*> putWord32 (ss2ScryptIter b)
       <*> putByteString (ss2Encrypted b)
       <*> putByteString (ss2VerifyTag b)


-- | A collection of related data connected to a specific SQRL profile.
data SecureStorageBlock =
  Block00001 SecureStorageBlock1     -- ^ The most basic of storage blocks. Contains information about master key and encryption settings.
  Block00002 SecureStorageBlock2     -- ^ Encrypted rescue code.
  BlockOther Int LBS.ByteString      -- ^ Any other block not supported by the specification at the time of writing, or chosen not to implement. Pull requests are welcome.

-- | A secure storage for a SQRL profile. Contains encrypted keys and SQRL settings.
data SecureStorage = SecureStorage Bool String [SecureStorageBlock]

-- | Get the whole block as a lazy 'LBS.ByteString'.
secureStorageData :: SecureStorageBlock -> LBS.ByteString
secureStorageData (Block00001 b) = encode b
secureStorageData (Block00002 b) = encode b
secureStorageData (BlockOther n bs) = LBS.append (runPut (putWord16 (4 + LBS.length bs) *> putWord16 n)) bs

-- | Get a structured version of the data contained by the block of type 1.
secureStorageData1 :: SecureStorage -> Maybe SecureStorageBlock1
secureStorageData1 (SecureStorage _ _ ss) = case find ((==) 1 . secureStorageType) ss of
  Just (Block00001 b) -> Just b
  _ -> Nothing

-- | Get a structured version of the data contained by the block of type 2.
secureStorageData2 :: SecureStorage -> Maybe SecureStorageBlock2
secureStorageData2 (SecureStorage _ _ ss) = case find ((==) 2 . secureStorageType) ss of
  Just (Block00002 b) -> Just b
  _ -> Nothing

-- | Get something specific out of the 'SecureStorageBlock'. Currently only accepts first block of each type.
secureStorageBlock :: Int -> SecureStorage -> Get a -> Maybe a
secureStorageBlock bt (SecureStorage _ _ ss) f = case find ((==) bt . secureStorageType) ss of
  Nothing -> Nothing
  Just sb -> case runGetOrFail f $ secureStorageData sb of
    Left _ -> Nothing
    Right (_, _, r) -> Just r

-- | Open a 'SecureStorage' contained within a 'LBS.ByteString'.
openSecureStorage' :: String -> LBS.ByteString -> Either String SecureStorage
openSecureStorage' fn bs = case runGet (oss []) bs of
  Left (_, pos, err) -> Left $ err ++ " (at position " ++ show pos ++ ")"
  Right (_, _, rslt) -> SecureStorage False fn $ reverse rslt
  where oss :: [SecureStorageBlock] -> Get [SecureStorageBlock]
        oss p = isEmpty >>= \e -> if e then p else do
          (l, t) <- (,) <$> getWord16 <*> getWord16
          r <- case t of
           1 -> Block00001 <$> get
           2 -> Block00002 <$> get
           _ -> BlockOther (fromIntegral t) <$> getLazyByteString $ fromIntegral (l - 32)
          let r' = r : p in seq r' $ oss r'

-- | Open a 'SecureStorage' contained within a file.
openSecureStorage :: FilePath -> IO (Either String SecureStorage)
openSecureStorage fp = withBinaryFile fp ReadMode (openSecureStorage' <$> LBS.hGetContent)

-- | Turn a 'SecureStorage' into a lazy 'LBS.ByteString'.
saveSecureStorage' :: SecureStorage -> LBS.ByteString
saveSecureStorage' (SecureStorage _ _ ss) = runPut $ mapM_ sss ss
  where sss :: SecureStorageBlock -> Put
        sss x = case x of
          Block00001 x'  -> put x'
          Block00002 x'  -> put x'
          BlockOther i b -> putWord16 (fromIntegral $ LBS.length b + 32) >> putWord16 (formIntegral i) >> putLazyByteString b

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
    , profileUsed          :: UTCTime
    , profileSecureStorage :: IO (Either String SecureStorage)
    }

dirSep :: String
dirSep = "/"

listProfilesInDir :: FilePath -> IO [SQRLProfile]
listProfilesInDir dir = do
  dd <- map (init . dropWhileEnd ('.'/=))  <$> filter (isSuffixOf ".ssss") <$> getDirectoryContents dir
  catMaybes <$> mapM openProfile dd
  where openProfile d' = case (if all (\x -> x > ' ' && x < 'z') d' then B64U.decode (BS.pack $ map (fromIntegral . fromEnum) d') else Left undefined) of
          Left _ -> return Nothing
          Right bs -> let f = dir ++ "/" ++ d' ++ ".time" in do
            t <- catch (getModificationTime f) (const (return 0) :: IOError -> IO UTCTime)
            return $ Just $ SQRLProfile (TE.decodeUtf8 bs) t $ openSecureStorage f

listProfiles :: MonadIO io => io [SQRLProfile]
listProfiles = liftIO $ profilesDirectory >>= listProfilesInDirs

profilesDirectory :: IO FilePath
profilesDirectory = getAppUserDataDirectory $ "sqrl" ++ dirSep ++ "profiles"

data ProfileCreationError
  = ProfileExists
  | RandomError0 GenError
  | RandomError1 GenError
  deriving (Show, Eq)

createProfileInDir :: Text -> Text -> Word8 -> Word16 -> Word8 -> ClientFlags -> FilePath -> IO (Either String (SQRLProfile, RescueCode))
createProfileInDir name pass hintl hintt time flags dir =
  let f = dir ++ dirSep ++ map (toEnum . fromIntegral) $ BS.unpack $ B64U.encode $ TE.encodeUtf8 name
  in doesFileExist f >>= \fx -> if fx then return $ Left "Profile already exists." else (genKeys <$> newGenIO) >>= \ekeys -> case ekeys of
      Left err -> return $ Left $ RandomError0 err
      Right (lockkey, unlockkey, rcode) -> (genEncParams <$> newGenIO) >>= \eencp -> case eencp of
        Left err -> return $ Left $ RandomError1 err
        Right (unlockKeyLogN, unlockKeyTime, idKeyLogN, idKeySalt, idKeyIV) -> do
          let idKey = ssEnhash' unlockKey
          (encIdKey, idKeyIter) <- encryptForSecs (fromintegral time) idKeyLogN idKeySalt idKey pass
          (encUnlockKey, unlockKeyIter) <- encryptForSecs (fromintegral unlockKeyTime) unlockKeyLogN emptySalt unlockKey rcode
          let (block1enc, idKeyTag) = undefined
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
               , ss1VerifyTag    = idKeyTag
               }
              ss = SecureStorage True (f ++ ".ssss") [Block00001 block1, BLock00002 block2]
          saveSecureStorage ss
  where genKeys = case ED25519.generateKeyPair g of
         Left err -> Left err
         Right (PublicKey lockkey, SecretKey unlockkey, g') -> case genRcode g' of
            Left err -> Left err
            Right (rcode, _) -> Right (lockkey, unlockkey, rcode)
        unlockKeyLogN = 200
        unlockKeyIter = 800
        genRcode g = genBytes 10 g >>= \x -> case x of
          Left err -> Left err
          Right (bsrcode, g') ->
            let rcode :: Integral
                rcode = runGet ((\(x, y) -> (fromIntegral x `shiftL` 8) .|. fromIntegral y) <$> getWord64 <*> getWord8) bsrcode
                resc' = show rcode
                rescl = length resc'
            in if rescl > 24 then genRcode g' else Right (T.pack $ replicate (rescl - 24) '0' ++ resc', g')

createProfile :: MonadIO io => Text -> Text -> Word8 -> Word16 -> Word8 -> ClientFlags -> io (Either String (SQRLProfile, RescueCode))
createProfile name pass hintl hintt time flags = liftIO (profilesDirectory >>= createProfileInDir name pass hintl hintt time flags)
