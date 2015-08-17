{-# LANGUAGE OverloadedStrings, MultiParamTypeClasses, CPP #-}
module Web.Authenticate.SQRL.Client.Simple where

import Web.Authenticate.SQRL.Types
import Web.Authenticate.SQRL.Client
import Web.Authenticate.SQRL.Client.Types
import Web.Authenticate.SQRL.Client.IO
import Web.Authenticate.SQRL.SecureStorage

import Data.IORef
import Data.Word (Word16)
import Data.Function (on)
import Data.List (sortBy)
import Data.Char (toLower, isUpper, isLower, isDigit, isSpace, isAlphaNum)
--import Data.Byteable
import Data.Bits
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import qualified Data.Text.Encoding as TE
import qualified System.IO as IO
import System.IO.Unsafe (unsafePerformIO)
import Data.ByteString (ByteString)
--import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HashMap
import Control.Concurrent.STM
import Control.Concurrent (forkIO)
import Control.Applicative
import Control.Monad (unless, foldM, foldM_, when, replicateM_)
import Control.Monad.IO.Class (liftIO)
import Control.DeepSeq (($!!))

import Data.Maybe (isNothing, fromJust, fromMaybe)
import System.Environment (getArgs)
import System.Directory (doesFileExist, doesDirectoryExist, getDirectoryContents, getTemporaryDirectory)

import Control.Exception (asyncExceptionFromException, bracket, catch, throwIO, SomeAsyncException, IOException)

import Crypto.Random
import Crypto.Cipher.AES
import qualified Data.Binary as Binary
import Data.Byteable


#if MIN_VERSION_base(4,7,0)
import System.Mem (performGC)
#endif

flush :: IO ()
flush = IO.hFlush IO.stdout

-- | The version of this client.
simpleClientVersion :: Text
simpleClientVersion = "0.0.0.0"

-- | The name of this client.
simpleClientName :: Text
simpleClientName = "Hasqrell Simple"

type Hint = (Text, SecureStorageBlock1)

-- | A 'TVar' containing the currently active user with a simplified encryption if the user has hinting allowed.
hinted :: TVar (Maybe Hint)
{-# NOINLINE hinted #-}
hinted = unsafePerformIO $ newTVarIO Nothing



-- | A simple client containing the current state.
data SimpleClient
  = SimpleClient
    { selectedProfile   :: Maybe SQRLProfile
    , masterIdentity    :: Maybe PrivateMasterKey
    , masterLock        :: Maybe PrivateLockKey
    , previousUnlock    :: Maybe PrivateUnlockKey
    , clientKeys        :: HashMap Text (DomainIdentityKey, Maybe DomainIdentityKey)
    , clientError       :: ClientErr
    }


-- | An empty client. Used to start a session and manipulating monadically.
emptyClient :: SimpleClient
emptyClient = SimpleClient Nothing Nothing Nothing Nothing HashMap.empty ClientErrNone

-- | The string representing a new line.
newline :: String
newline = "\n"

-- | Useful for debugging. Displays no master keys, only domain keys.
instance Show SimpleClient where
  show (SimpleClient { selectedProfile = mp, masterIdentity = mi, masterLock = ml, previousUnlock = pu, clientKeys = ck, clientError = ce }) = concat
    [ "SimpleClient { selectedProfileName = ", show (fmap profileName mp), newline
    , "             , masterIdentity = ", hidedata mi, newline
    , "             , masterLock = ", hidedata ml, newline
    , "             , previousUnlock = ", hidedata pu, newline
    , "             , clientKeys = ", show ck, newline
    , "             , clientError = ", show ce, newline
    , "             }"
    ]
    where hidedata :: Maybe a -> String
          hidedata m = case m of { Nothing -> "Nothing" ; Just _ -> "Just <hidden-data>" }

-- | The 'SimpleClient' is a SQRL client.
instance SQRLClientM SimpleClient IO where
  sqrlClientName _ = simpleClientName
  sqrlClientAuthor _ = "Tim Lundqvist"
  sqrlClientContact _ = "@TimLuq"
  sqrlClientVersion _ = simpleClientVersion

  sqrlAskClient = askClientSimple
  sqrlAccountAssociation = accountAssociationSimple
  sqrlLoginAccount = loginAccountSimple

  sqrlIdentityKey url = sqrlClient $ \s -> case HashMap.lookup dom $ clientKeys s of
    Just (k, _) -> return (s, k)
    Nothing -> s `runClient'` (loadKeys url >> sqrlIdentityKey url)
    where dom = sqrlUrlOrigin url
  sqrlIdentityKeyPrevious url = sqrlClient $ \s -> case HashMap.lookup dom $ clientKeys s of
    Just (_, k) -> return (s, k)
    Nothing -> s `runClient'` (loadKeys url >> sqrlIdentityKeyPrevious url)
    where dom = sqrlUrlOrigin url

  readClientError SimpleClient { clientError = e } = return e
  setClientError e = sqrlClient $ \s -> return (s { clientError = e }, ())

  sqrlClearHint  = sqrlClient' $ const clearHint
  sqrlClearSensitive = sqrlClient $ \s -> returnClear s { masterIdentity = Nothing, masterLock = Nothing, previousUnlock = Nothing, clientKeys = HashMap.empty }
    where
#if MIN_VERSION_base(4,7,0)
      returnClear s' = seq s' (performGC >> return (s', ()))
#else
      returnClear = return . flip (,) ()
#endif

  generateUnlockKeys = generateUnlockKeys_ $ sqrlClient $ \s -> case masterLock s of
    Nothing -> return (s { clientError = ClientErrNoProfile }, error "generateUnlockKeys: No keys could be generated due to no profile being active.")
    Just ml -> return (s, ml)
    

errorMessage :: SimpleClient -> Maybe String
errorMessage (SimpleClient { clientError = err }) = case err of
  ClientErrNone -> Nothing
  _ -> Just (show err)

-- | A monadic wraper which 'fail's when an error is defined in the 'SimpleClient' (via 'clientError').
sqrlClient_ :: (SimpleClient -> IO (SimpleClient, t)) -> SQRLClient SimpleClient IO t
sqrlClient_ f = testFail () >> sqrlClient f >>= testFail
  where testFail :: t -> SQRLClient SimpleClient IO t
        testFail r = sqrlClient' $ \s' -> case errorMessage s' of
          Nothing -> return r
          Just er -> fail er

-- | Generate keys for a specific domain and store in current session.
-- This may cause the monad to 'fail' if the decryption is unsuccessful or no profile is selected.
loadKeys :: SQRLUrl -> SQRLClient SimpleClient IO ()
loadKeys url = sqrlClient_ $ \s -> flip (,) () <$> case selectedProfile s of
  Nothing -> return s { clientError = ClientErrNoProfile }
  Just pr -> do
    let name = profileName pr
    (s', imk, pmk) <- case masterIdentity s of
      Just imk' -> return (s, imk', previousUnlock s)
      Nothing   -> do
        mh <- atomically $ readTVar hinted
        if isNothing mh || fst (fromJust mh) /= name
         then profileSecureStorage pr >>= \x -> case x of
           Left er -> return (s { clientError = ClientErrSecureStorage er }, mkPrivateKey empty256, Nothing)
           Right r -> decryptWith (password name) (fromJust $ secureStorageData1 r) >>= decrResult s
         else decryptWith (passwordHint name) (snd $ fromJust mh) >>= decrResult s
    return $ case clientError s' of
              ClientErrNone -> s' { clientKeys = HashMap.insert (sqrlUrlOrigin url) (deriveDomainKey url (imk :: PrivateMasterKey), deriveDomainKey url <$> (pmk :: Maybe PrivateUnlockKey)) (clientKeys s') }
              _ -> s'
  where decrResult :: SimpleClient -> Either String SecureStorageBlock1Decrypted -> IO (SimpleClient, PrivateMasterKey, Maybe PrivateUnlockKey)
        decrResult s x1 = case x1 of
          Left er -> return (s { clientError = ClientErrDecryptionFailed er }, mkPrivateKey empty256, Nothing)
          Right d -> let imk' = identityMasterKey d
                         lmk' = identityLockKey d
                         pmk' = previousUnlockKey d
                     in return (s { masterIdentity = Just imk', masterLock = Just lmk', previousUnlock = pmk' }, imk', pmk')
        password :: Text -> SecureStorageBlock1 -> IO Text
        password name _ = passinfo name >> T.pack <$> readPassword "Password"
        passwordHint :: Text -> SecureStorageBlock1 -> IO Text
        passwordHint name ss1 = passinfo name >> (T.pack . take (fromIntegral $ ss1HintLen ss1)) <$> readPassword "Password hint: "
        passinfo name = putStrLn "" >> putStrLn ("Using account " ++ show name ++ " to connect to " ++ show (sqrlUrlOrigin url) ++ ".") >> putStrLn ""
        decryptWith :: (SecureStorageBlock1 -> IO Text) -> SecureStorageBlock1 -> IO (Either String SecureStorageBlock1Decrypted)
        decryptWith f ss1 = fmap (\r -> case r of { Nothing -> Left "Wrong password." ; Just  r' -> Right r' }) (flip ssDecrypt ss1 <$> f ss1) `catch` \e ->
          case asyncExceptionFromException e of
           Just e' -> throwIO (e' :: SomeAsyncException)
           Nothing -> return $ Left $ show e


askClientSimple :: (AskResponse -> SQRLClient SimpleClient IO ()) -> SQRLClient SimpleClient IO () -> SQRLAsk -> SQRLUrl -> SQRLServerData ByteString -> SQRLClient SimpleClient IO ()
askClientSimple onsucc onabort ask url sdata = do
  r <- liftIO $ do
    putStrLn ""
    putStrLn $ "----- Ask: " ++ init (tail $ show $ serverFriendlyName sdata) ++ " (" ++ init (tail $ show $ sqrlUrlOrigin url) ++ ") -----"
    putStrLn ""
    putStr " Describing message:"
    putStrLn $ concatMap ((++) "\r\n    " . filter (>= ' ') . T.unpack) (T.lines $ askMessage ask)
    putStrLn ""
    putStrLn "-1. Abort"
    putStrLn " 0. Default"
    foldM_ (\i (txt, vurlm) -> const (i+1) <$> putStrLn (show (i :: Int) ++ ". " ++ init (tail $ show txt) ++ fromMaybe "" ((\x -> "(opens " ++ show x ++ ")") <$> vurlm))) 1 (askButtons ask)
    putStrLn ""
    readIt "Choice" 0 $ \x -> if x >= (-1) && x <= length (askButtons ask) then Nothing else Just "That is not one of the options."
  case (r :: Int) of
   -1 -> onabort
   _  -> onsucc $ toEnum r -- TODO: send browser to page, if any

loginAccountSimple :: (SQRLCommandAction -> SQRLClient SimpleClient IO ()) -> SQRLClient SimpleClient IO () -> SQRLUrl -> SQRLServerData ByteString -> SQRLClient SimpleClient IO ()
loginAccountSimple executeCommand onabort url sdata = do
  a <- liftIO $ do
    putStrLn $ "----- Connection: " ++ init (tail $ show $ serverFriendlyName sdata) ++ " (" ++ init (tail $ show $ sqrlUrlOrigin url) ++ ") -----"
    putStrLn ""
    putStrLn $ " A connection has been made to a site calling itself " ++ show (serverFriendlyName sdata) ++ "."
    putStrLn ""
    putStrLn " Which action do you wish to take?"
    putStrLn ""
    putStrLn " 0. None"
    putStrLn " 1. Identify"
    putStrLn ""
    readIt "Action" 1 $ \x -> if x >= 0 && x <= 1 then Nothing else Just (show x ++ " is not a valid action.")
  case (a :: Int) of
   0 -> onabort
   1 -> executeCommand IDENT
   _ -> liftIO (IO.hPutStrLn IO.stderr "!!! Illegal action chosen -> aborting connection.") >> onabort

accountAssociationSimple :: SQRLClient SimpleClient IO () -> SQRLClient SimpleClient IO () -> SQRLUrl -> SQRLServerData ByteString -> SQRLClient SimpleClient IO ()
accountAssociationSimple onaccept ondeny url sdata = (=<<) (\r -> if r then onaccept else ondeny) $ liftIO $ do
  putStrLn ""
  putStrLn $ "----- New association: " ++ init (tail $ show $ serverFriendlyName sdata) ++ " (" ++ init (tail $ show $ sqrlUrlOrigin url) ++ ") -----"
  putStrLn ""
  putStrLn $ " You have no previous account connected to this profile for this site. The site is calling itself " ++ show (serverFriendlyName sdata) ++ "."
  putStrLn ""
  putStrLn " Do you wish to connect your identity to this site?"
  putStrLn ""
  readBool "Continue" True
  

-- | As with 'getLine' but with password. The integer parameter is a strength modifier which, if a natural number defines the strength requirement of the password.
getPassword :: Int         -- ^ password stength modifier (negative disables, 0 normal, higher values makes it more difficult)
            -> IO String
getPassword b = bracket (IO.hGetEcho IO.stdin) (IO.hSetEcho IO.stdin) $ const $
  IO.hSetEcho IO.stdin False >> getLine >>= \p -> putStrLn (if b >= 0 then " < " ++ show (passwordStrength b p) ++ " >" else "") >> return p

newPassword :: String -> Int -> IO String
newPassword t i = putStr ((' ':t) ++ ": ") >> flush >> getPassword i

readPassword :: String -> IO String
readPassword t = putStr ((' ':t) ++ ": ") >> flush >> getPassword (-1)

data PasswordStrength
  = BadPassword
  | WeakPassword
  | MediumPassword
  | GoodPassword
  | StrongPassword
  deriving (Show, Eq, Enum, Ord)

-- | Quick approximation of password quality.
passwordStrength :: Int -> String -> PasswordStrength
passwordStrength pw pass'
  | points < 2 * pw + (1 + (pw `div` 10)) * 10   = BadPassword
  | points < 2 * pw + (1 + (pw `div` 10)) * 32   = WeakPassword
  | points < 2 * pw + (1 + (pw `div` 10)) * 64   = MediumPassword
  | points < 2 * pw + (1 + (pw `div` 10)) * 128  = GoodPassword
  | otherwise              = StrongPassword
  where pass = take 200 pass'
        countGroups :: String -> (Char -> Bool) -> Int
        countGroups x f = case span f x of
          ("",  ""  ) -> 0
          ("",  _:x') -> countGroups x' f
          (_:_, ""  ) -> 1
          (_:_, _:x') -> 1 + countGroups x' f
        countConsec :: String -> (Int -> Bool) -> (Char -> Bool) -> [String]
        countConsec x s f = case span f x of
          ("", ""  ) -> []
          ("", _:x') -> countConsec x' s f
          (r,  ""  ) -> [r | (s . length) r]
          (r,  _:x') -> if s (length r) then r : countConsec x' s f else countConsec x' s f
        points = sum
          [ 2 * length (take 12 pass)
          , 3 * length (take 6 $ drop 12 pass)
          , 4 * length (drop 18 pass)
          , sum $ map ((-) 4 . (*) 2 . length) $ countConsec pass (>3) isDigit
          , sum $ map ((-) 4 . (*) 2 . length) $ countConsec pass (>3) isUpper
          , sum $ map ((-) 4 . (*) 2 . length) $ countConsec pass (>3) isLower
          , sum $ map ((-) 4 . (*) 2 . length) $ countConsec pass (>3) (not . isAlphaNum)
          , flip (-) 8 $ 4 * countGroups pass isDigit
          , flip (-) 8 $ 4 * countGroups pass isUpper
          , flip (-) 8 $ 4 * countGroups pass isLower
          , flip (-) 8 $ 4 * countGroups pass (not . isAlphaNum)
          ]

-- | Clears any current user and hinting mechanisms.
clearHint :: IO ()
clearHint =
  putStrLn "TRACE: clearing hint..." >>
  atomically (writeTVar hinted Nothing)
  <* putStrLn "TRACE: hint cleared."
#if MIN_VERSION_base(4,7,0)
  <* performGC
#endif

-- | This client uses 'SecureStorage' for it's profile management.
instance SecureStorageProfile SimpleClient IO where
  sspShowProfiles = showProfilesSimple
  sspCurrentProfile = selectedProfile
  sspCreateProfile = createProfileSimple

showProfilesSimple :: Text -> (SimpleClient -> IO ()) -> [SQRLProfile] -> IO ()
showProfilesSimple actiondesc mf ps = let ps_ = sortBy (compare `on` profileUsed) ps in do
    putStrLn "TRACE: checking hinting possibilities..."
    hntd <- atomically $ readTVar hinted
    putStrLn "TRACE: hinting possibilities received."
    putStrLn "" >> putStr "------- " >> T.putStr (if T.null actiondesc then "Profiles" else actiondesc) >> putStrLn " -------"
    let (ps', andAlso) = case hntd of
          Nothing -> (take 8 ps_, return ())
          Just (nm, _) -> (take 8 $ filter ((/=) nm . profileName) ps_, putStr " 9. " >> T.putStrLn nm >> putStrLn "")
    foldM_ displayUser 1 ps'
    andAlso
    putStrLn ""
    putStrLn " 0 - Create new profile"
    putStrLn ""
    putStr "Choice or search"
    when (actiondesc /= T.empty) (putStr " for " >> T.putStr actiondesc)
    putStr ": "
    flush
    r <- getLine
    case r of
     "0" -> createProfileSimple createProfile mf "" ""
     [x] -> if x > '0' && x <= head (show $ length ps')
               then chooseProfileSimple Nothing actiondesc mf $ ps' !! (fromEnum x - fromEnum '1')
               else case (x, hntd) of
                     ('9', Just _) -> chooseProfileSimple hntd actiondesc mf $ ps' !! (fromEnum x - fromEnum '1')
                     _ -> sspShowProfiles actiondesc mf $ filter (T.isInfixOf (T.singleton x) . profileName) ps_
     _   -> sspShowProfiles actiondesc mf $ filter (T.isInfixOf (T.pack r) . profileName) ps_
  where displayUser :: Int -> SQRLProfile -> IO Int
        displayUser n p =  putStr (" " ++ show n ++ ". ") >> T.putStrLn (profileName p) >> putStr "    last used: " >> print (profileUsed p) >> return (n + 1)

chooseProfileSimple :: Maybe Hint -> Text -> (SimpleClient -> IO ()) -> SQRLProfile -> IO ()
chooseProfileSimple hint _{-actiondesc-} mf prof =
  case hint of
   Nothing -> fromScratch 2
   Just (_, hw) -> askHint hw
  where fromScratch :: Int -> IO ()
        fromScratch 0 = do
          clearHint
          errorClient ClientErrWrongPassword
        fromScratch n = do
          ess <- profileSecureStorage prof
          case secureStorageData1 <$> ess of
           Left err -> errorClient $ ClientErrSecureStorage err
           Right Nothing -> errorClient $ ClientErrSecureStorage "SecureStorage contains no BLOCK1 - which it really should."
           Right (Just ss1) -> do
             pass <- T.pack <$> readPassword "Password"
             case ssDecrypt pass ss1 of
              Nothing -> fromScratch (n-1)
              Just de -> do
                _ <- forkIO $ storeHint ss1 de (profileName prof) pass
                mf emptyClient { selectedProfile = Just prof, masterIdentity = Just $ identityMasterKey de, masterLock = Just $ identityLockKey de, previousUnlock = previousUnlockKey de }
        askHint ss1 = do
          mdec <- flip ssDecrypt ss1 . T.pack . take (fromIntegral $ ss1HintLen ss1) <$> readPassword "Password hint"
          case mdec of
           Nothing -> clearHint >> fromScratch 1
           Just de -> mf emptyClient { selectedProfile = Just prof, masterIdentity = Just $ identityMasterKey de, masterLock = Just $ identityLockKey de, previousUnlock = previousUnlockKey de }
        storeHint :: SecureStorageBlock1 -> SecureStorageBlock1Decrypted -> Text -> Text -> IO ()
        storeHint ss1 de user pass = do
          g <- newGenIO :: IO SystemRandom
          let (salt0, g') = throwLeft $ genBytes 32 g
              (salt1, _ ) = throwLeft $ genBytes 32 g'
              ss1' = ss1 { ss1CryptoIV = salt0, ss1ScryptSalt = salt1, ss1ScryptLogN = 9, ss1ScryptIter = 10 }
              pass' = enScrypt 10 9 salt1 $ T.take (fromIntegral $ ss1HintLen ss1) pass
              (block1enc, idKeyTag) = encryptGCM (initAES pass') salt0 (ssAAD ss1') $ LBS.toStrict $ Binary.encode de
              ss1'' = block1enc `seq` ss1' { ss1Encrypted = block1enc, ss1VerifyTag = toBytes idKeyTag }
          seq ss1'' $ atomically $ writeTVar hinted $ Just (user, ss1'')
        errorClient x = putStrLn (" User interaction caused " ++ show x)>> mf emptyClient { clientError = x }

createProfileSimple :: ((ProfileCreationState -> IO ())    -- ^ a callback which gets notified when the state changes
                        -> IO SQRLEntropy                  -- ^ an external source of entropy (recommended n_bytes > 512), if none is available @return NoEntropy@ should produce a working result
                        -> Text                            -- ^ name of this profile (may not collide with another)
                        -> Text                            -- ^ password for this profile
                        -> HintLength                      -- ^ the length the password hint should be (see 'HintLength')
                        -> Word16                          -- ^ the time, in minutes, before a hint should be wiped
                        -> PWHashingTime                   -- ^ the amount of time should be spent hashing the password
                        -> ClientFlags                     -- ^ client settings for this profile
                        -> IO (Either ProfileCreationError (SQRLProfile, RescueCode))
                       )              -- ^ recommended function for profile creation
                    -> (SimpleClient -> IO ()) -- ^ action to run with the new profile
                    -> Text           -- ^ requested profile name (MAY be overriden or confirmed)
                    -> Password       -- ^ requested password (MAY be overriden or confirmed)
                    -> IO ()
createProfileSimple pf cf rname _ =
  let 
  in do putStrLn ""
        putStrLn "---- Creating a new profile ----"
        putStrLn ""
        name <- T.pack <$> readString "Profile name" (T.unpack rname)
        pass <- T.pack <$> (newPassword "Password" 0 >>= untilRepeatM (==) (newPassword "Repeat last password" 0))
        hntl <- readIt "Password hint length" 4 $ \x ->
          if x < 3 then Just "Hint must be at least 3 characters long"
          else if x >= T.length pass then Just "Hint must be shorter than the password"
               else Nothing
        hntt <- readIt "Password hint timeout (minutes)" 45 $ const Nothing
        pwht <- readIt "Password hashing time (seconds)" 10 $ \x ->
          if x < 10 then Just "With a short hashing time a brute force attack may be possible."
          else Nothing
        -- get client flags
        putStrLn ""
        putStrLn "---- Profile settings ----"
        putStrLn ""
        flgs <- foldM (\s (f, d, t) -> (\r -> if r then f .|. s else s) <$> readBool t d) 0
                [ (clientFlagAutoUpdate,        True,   "AutoUpdt | Allow client to look for updates                                   ")
                , (clientFlagNoCurrentProfile,  False,  "NoCurrnt | No profile is the current one, so hint is disabled                 ")
                , (clientFlagSQRLOnly,          False,  "SQRLOnly | Request every server to disable any other authentication methods   ")
                , (clientFlagHardLock,          False,  "HardLock | Request every server to disable any other account recovery methods ")
                , (clientFlagWarnMITM,          True,   "WarnMITM | Warn if man-in-the-middle is detected                              ")
                , (clientFlagClearOnBlack,      True,   "ClrBlack | Clear profile hint when detecting screensaver or suspend           ")
                , (clientFlagClearOnUserSwitch, True,   "ClrSwtch | Clear profile hint when switching users                            ")
                , (clientFlagClearOnIdle,       True,   "ClrOnIdl | Clear profile hint after the account has been idle                 ")
                ]
        putStrLn ""
        putStrLn "---- Building profile ----"
        putStrLn ""
        r <- pf showCreationProgress getEntropy name pass (fromIntegral hntl) hntt pwht flgs
        putStrLn ""
        case r of
         Left err -> putStrLn " -- Profile creation failed:" >> putStrLn (unlines $ map ((:) ' ' . (:) ' ' . (:) ' ' . (:) ' ') $ lines $ show err) >> putStrLn " -- Press enter to continue" >> const () <$> getLine
         Right (prof, RescueCode rcode) -> do
           putStrLn "---- Profile complete ----"
           putStrLn ""
           putStr   " Rescue code: " >> T.putStrLn (T.unwords $ T.chunksOf 4 rcode)
           putStrLn ""
           putStrLn " Write the above series of numbers on a note and store it securly."
           putStrLn " The rescue code is the only way of rekeying, and thereby regaining control, of all accounts if your master key is lost or has fallen into someone elses possession."
           putStrLn " If possible write half the numbers on one note and store it securly at home and the other half on another note and store one copy in your wallet and the other in a vault at a bank."
           putStrLn ""
           putStrLn " -- Press enter after writing down the rescue code to a piece of paper."
           _ <- getLine
           replicateM_ 40 $ putStrLn ""
           putStrLn " Verify your rescue code by typing it in."
           putStr " rescue code: " >> flush
           rcode' <- T.pack . filter (not . isSpace) <$> getLine
           when (rcode' /= rcode) (putStr " No. That was wrong. The correct one is: " >> T.putStrLn (T.unwords $ T.chunksOf 4 rcode) >> putStrLn "" >> putStrLn " -- Press enter when you've correctly written it down." >> const () <$> getLine)
           replicateM_ 40 $ putStrLn ""
           cf emptyClient { selectedProfile = Just prof }
  where getEntropy = putStrLn "Entropy is gathering..." >>
          systemSpecificEntropy >>= \x -> let f = (getTemporaryDirectory >>= readIfFileOrFilesInDir 2 entropyGathered) in if null x then f else return (SQRLEntropy x f)
        entropyGathered = putStrLn "Entropy has been gathered." >> return NoEntropy
        readIfFileOrFilesInDir :: Int -> IO SQRLEntropy -> FilePath -> IO SQRLEntropy
        readIfFileOrFilesInDir 0 f _ = f
        readIfFileOrFilesInDir d f fp = doesDirectoryExist fp >>= \isDir ->
          if isDir then getDirectoryContents fp >>= entropyDirs (d-1) f . map ((fp ++ dirSep) ++)
          else readIfFile f fp
        readIfFile f fp = doesFileExist fp >>= \isFile -> if isFile
          then fmap (`SQRLEntropy` f) (newIORef [] >>= \ioref -> IO.withBinaryFile fp IO.ReadMode (\h -> (LBS.toChunks <$> LBS.hGetContents h) >>= \r -> writeIORef ioref $!! r) >> readIORef ioref)
               `catch` (const f :: IOException -> IO SQRLEntropy)
          else f
        entropyDirs _ f [] = f
        entropyDirs d f (fp:fps) = readIfFileOrFilesInDir d (entropyDirs d f fps) fp
        -- | This returns some semistatic data depending on your hardware. This should be unique for every physical computer.
        systemSpecificEntropy :: IO [ByteString]
        systemSpecificEntropy = map (TE.encodeUtf8 . T.pack) <$> getDirectoryContents "/dev/disk/by-uuid"
        showCreationProgress :: ProfileCreationState -> IO ()
        showCreationProgress pcs = let prct = show $ profileCreationPercentage pcs in putStrLn  $ replicate (5 - length prct) ' ' ++ prct ++ "%    " ++ profileCreationMessage pcs
        untilRepeatM :: Monad m => (a -> a -> Bool) -> m a -> a -> m a
        untilRepeatM f m t = m >>= \t' -> if f t t' then return t else untilRepeatM f m t'
                                                                  

readString :: String -> String -> IO String
readString t d = putStr (concat $ (:) (' ':t) $ (if null d then id else (:) " [" . (:) d . (:) "]") [": "]) >> flush >> getLine >>= \l ->
        if null l then if null d then readString t d else return d else return l
readIt :: (Show a, Read a) => String -> a -> (a -> Maybe String) -> IO a
readIt t d vf = readString t (show d) >>= \l ->
  ( (readIO l >>= \a -> case vf a of { Nothing -> return a ; Just err -> putStrLn (" -- " ++ err) >> readIt t d vf })
    `catch` ((\d' vf' _ -> putStrLn " -- invalid input value" >> readIt t d' vf') :: (Show a, Read a) => a -> (a -> Maybe String) -> IOException -> IO a) d vf
  )
trim :: String -> String
trim = reverse . dropWhile (' ' ==) . reverse . dropWhile (' ' ==)
readBool :: String -> Bool -> IO Bool
readBool t d = readString t (if d then "True " else "False") >>= \x -> let x' = trim $ map toLower x in
  if x' `elem` ["t", "true", "yes", "y", "1"] then return True
  else if x' `elem` ["f", "false", "no", "n", "0"] then return False
       else putStrLn " -- invalid boolean input" >> readBool t d


-- | Entry point for the application.
main :: IO ()
main = do
  args <- getArgs
  case args of
   ("import":_) -> mainImport $ tail args
   ("sign":_)   -> mainSign $ tail args
   ("-h":_)     -> mainHelp $ tail args
   ("--h":_)    -> mainHelp $ tail args
   ("--help":_) -> mainHelp $ tail args
   ("-help":_)  -> mainHelp $ tail args
   ("--version":_) -> mainVersion
   ("-version":_)  -> mainVersion
   ("version":_)   -> mainVersion
   (('q':'r':'l':':':'/':'/':_):_) -> mainSign args
   (('s':'q':'r':'l':':':'/':'/':_):_) -> mainSign args
   _ -> mainMenu

-- | Displays the version information.
mainVersion :: IO ()
mainVersion = T.putStrLn $ T.unwords [simpleClientName, simpleClientVersion]
-- | Imports a SQRL file to the profile storage.
mainImport :: [String] -> IO ()
mainImport args = case take 3 args of
  []            -> importHelp
  ("help":_)    -> importHelp
  [f]           -> getLine >>= importFileAs f
  [f,"as",n]    -> importFileAs f n
  ["-name",n,f] -> importFileAs f n
  ["-name",n]   -> importFileAs "-" n
  _             -> importHelp
  where importHelp = do
          putStrLn "   usage:  sqrl-auth-client-simple import <FILE> [as <PROFILE_NAME>]"
          putStrLn "           sqrl-auth-client-simple import -name <PROFILE_NAME> <FILE>"
          putStrLn "   Tries to import an existing SQRL identity contained in FILE by asking for a new profile name if none is provided."
        importFileAs f n = (if f == "-" then openSecureStorage' "/dev/null" <$> (IO.hSetBinaryMode IO.stdin True >> LBS.hGetContents IO.stdin) else openSecureStorage f) >>= \mss -> case mss of
          Left err -> IO.hPutStrLn IO.stderr err
          Right ss -> profilePath (T.pack n) >>= \ep -> case ep of
            Right _ -> IO.hPutStrLn IO.stderr $ "The profile " ++ show n ++ " already exists."
            Left  p -> saveSecureStorage (copySecureStorage p ss) >> putStrLn ("Profile " ++ show n ++ " has been imported with your previous password.")
mainHelp :: [String] -> IO ()
mainHelp _ = mainVersion >> putStrLn "" >> putStrLn "   usage:  sqrl-auth-client-simple [ SQRL-URI | sign | import | version ]"
mainSign :: [String] -> IO ()
mainSign args = case args of
  [sqrlurl@('s':'q':'r':'l':':':'/':'/':_:_)] -> signUrl sqrlurl
  [sqrlurl@('q':'r':'l':':':'/':'/':_:_)]     -> signUrl sqrlurl
  _ -> signHelp
  where signHelp = do
          putStrLn "   usage:  sqrl-auth-client-simple sign \"sqrl://example.com?nut=123\""
          putStrLn "   Starts a SQRL communication to the server and tries to verify an identity to the server."
        signUrl url = case readSQRLUrl (T.pack url) of
          Left er -> IO.hPutStrLn IO.stderr (" Invalid SQRL url: " ++ show url ++ " (" ++ er ++ ")")
          Right u -> do
            putStrLn "TRACE: Setting up thread block."
            var <- newEmptyTMVarIO
            putStrLn "TRACE: Displaying profile selection."
            sqrlChooseProfile "SQRL URL response" $ sqrlConnectionFlow (liftIO . atomically . putTMVar var :: ClientErr -> SQRLClient SimpleClient IO ()) u
            putStrLn "TRACE: Executing thread block while waiting."
            err <- atomically $ readTMVar var
            putStrLn "TRACE: Thread unblocked."
            case err of
             ClientErrNone -> putStrLn "Itentification succeded"
             _ -> IO.hPutStrLn IO.stderr $ "Identification failed: " ++ show err
mainMenu :: IO ()
mainMenu = do
  let choices = [ ("Display profiles", listProfiles >>= showProfilesSimple "Profile Management" profileManagement >> mainMenu)
                , ("Enter SQRL-URI", readString "SQRL URL" "" >>= \x -> mainSign [x] >> mainMenu)
                ]
      choicesl = length choices
  putStrLn "" >> putStrLn ("-------- " ++ T.unpack simpleClientName ++ " ---------") >> putStrLn ""
  foldM_ (\n (t, _) -> const (n+1) <$> putStrLn ("  " ++ show n ++ ".  " ++ t)) (1 :: Int) choices
  putStrLn ""
  putStrLn "  0.  Exit"
  putStrLn ""
  c <- readIt "Choice" 0 $ \n -> if n `elem` [0..choicesl] then Nothing else Just "number is outside of range"
  unless (c == 0) $ snd $ choices !! (c-1)

profileManagement :: SimpleClient -> IO ()
profileManagement _ = putStrLn "not implemented" >> mainMenu
