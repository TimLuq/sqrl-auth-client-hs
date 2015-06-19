{-# LANGUAGE OverloadedStrings #-}
module Web.Authenticate.SQRL.SecureStorage where

import Web.Authenticate.SQRL
import Web.Authenticate.SQRL.Client

data SecureStorageBlock1
  = SecureStorageBlock1
    { ss1CryptoIV     :: ByteString
    , ss1ScryptSalt   :: ByteString
    , ss1ScryptLogN   :: Word8
    , ss1ScryptIter   :: Word32
    , ss1Flags        :: ClientFlags
    , ss1HintLen      :: Word8
    , ss1HintIdle     :: Word16
    , ss1PlainExtra   :: ByteString
    , ss1MasterKey    :: MasterKey
    , ss1LockKey      :: PrivateKey
    , ss1UnlockKey    :: UnlockKey
    , ss1EncryptExtra :: ByteString
    , ss1VerifyTag    :: ByteString
    }

type ClientFlags = Word16

-- | This requests, and gives the SQRL client permission, to briefly check-in with its publisher to see whether any updates to this software have been made available.
clientFlagAutoUpdate :: ClientFlags
clientFlagAutoUpdate = 0x0001

-- | Where a SQRL client is loaded with multiple identities, this prevents the client from assuming any “current user” and causes it to prompt its operator for which identity should be used for every authentication. This can be useful when multiple users share a computer to keep any user from inadvertently attempting to use another user's identity.
clientFlagNoCurrentProfile :: ClientFlags
clientFlagNoCurrentProfile = 0x0002

-- | This adds the @option=sqrlonly@ string to every client transaction. When this option string is present in any properly signed client transaction, this requests the server to set a flag in the user account that will cause the web server to subsequently disable all traditional non-SQRL account logon authentication such as username and password.
clientFlagSQRLOnly :: ClientFlags
clientFlagSQRLOnly = 0x0004

-- | This adds the @option=hardlock@ string to every client transaction. When this option string is present in any properly signed client transaction, this requests the server to set a flag in the user account that will cause the web server to subsequently disable all “out of band” (non-SQRL) account identity recovery options such as “what was your favorite pet's name.”
clientFlagSQRLOnly :: ClientFlags
clientFlagSQRLOnly = 0x0008

-- | When set, this bit instructs the SQRL client to notify its user when the web server indicates that an IP address mismatch exists between the entity that requested the initial logon web page containing the SQRL link URL (and probably encoded into the SQRL link URL's “nut”) and the IP address from which the SQRL client's query was received for this reply.
clientFlagWarnMITM :: ClientFlags
clientFlagWarnMITM = 0x0010

-- | When set, this bit instructs the SQRL client to wash any existing local password and hint data from RAM upon notification that the system is going to sleep in any way such that it cannot be used. This would include sleeping, hibernating, screen blanking, etc.
clientFlagDiscardOnBlack :: ClientFlags
clientFlagDiscardOnBlack = 0x0020

-- | When set, this bit instructs the SQRL client to wash any existing local password and hint data from RAM upon notification that the current user is being switched.
--
-- Notice: This could be interpreted as refering to the SQRL profile as in 'clientFlagNoCurrentProfile', but in actuality the "user" above is the user controlled by the OS. I could see it being used either way, though.
clientFlagDiscardOnUserSwitch :: ClientFlags
clientFlagDiscardOnUserSwitch = 0x0040

-- | When set, this bit instructs the SQRL client to wash any existing local password and hint data from RAM when the system has been user-idle (no mouse or keyboard activity) for the number of minutes specified by the two-byte idle timeout.
--
-- Notice: The idle time in 'SecureStorageBlock1' is in minutes, when time=0 then no hint is allowed. It is quite clear that this is idle system-wide and not only in usage of SQRL. But since the idle time is allowed to be more than a month; a developer could see this as clearing the hint after being idle in the sense of no SQRL authentications for the specified amounts of minutes.
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
                                           <*> getByteString (blocklen - ptlen - 112)                                 -- additional encrypted data
                                           <*> getByteString 16                                                       -- auth tag
  put b =  putWord16 (157 + BS.length (ss1PlainExtra b) + BS.length (ss1EncryptExtra b)) <*> putWord16 1 
       <*> putWord16 (45 + BS.length (ss1PlainExtra b))
       <*> putByteString (ss1CryptoIV b) <*> putByteString (ss1ScryptSalt b)
       <*> putWord8 (ss1ScryptLogN b) <*> putWord32 (ss1ScryptIter b)
       <*> putWord16 (ss1Flags b) <*> putWord8 (ss1HintLen b) <*> putWord16 (ss1HintIdle b)
       <*> putByteString (ss1PlainExtra b)
       <*> putByteString (ss1MasterKey b) <*> putByteString (ss1LockKey b)
       <*> putByteString (ss1UnlockKey b) <*> putByteString (ss1EncryptExtra b)
       <*> putByteString (ss1VerifyTag b)


-- | A collection of related data connected to a specific SQRL profile.
data SecureStorageBlock =
  Block00001 SecureStorageBlock1 -- ^ The most basic of storage blocks. Contains information about master key and encryption settings.
  BlockOther Int LBS.ByteString      -- ^ Any other block not supported by the specification at the time of writing, or chosen not to implement. Pull requests are welcome.

-- | A secure storage for a SQRL profile. Contains encrypted keys and SQRL settings.
data SecureStorage = SecureStorage String [SecureStorageBlock]

-- | Get the whole block as a lazy 'LBS.ByteString'.
secureStorageData :: SecureStorageBlock -> LBS.ByteString
secureStorageData (Block00001 b) = encode b
secureStorageData (BlockOther _ bs) = bs

-- | Get a structured version of the data contained by the block of type 1.
secureStorageData1 :: SecureStorage -> Maybe SecureStorageBlock1
secureStorageData1 (SecureStorage _ ss) = case find ((==) 1 . secureStorageType) ss of
  Just (Block00001 b) -> Just b
  _ -> Nothing

-- | Get something specific out of the 'SecureStorageBlock'. Currently only accepts first block of each type.
secureStorageBlock :: Int -> SecureStorage -> Get a -> Maybe a
secureStorageBlock bt (SecureStorage _ ss) f = case find ((==) bt . secureStorageType) ss of
  Nothing -> Nothing
  Just sb -> case runGetOrFail f $ secureStorageData sb of
    Left _ -> Nothing
    Right (_, _, r) -> Just r

