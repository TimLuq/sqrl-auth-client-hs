module Web.Authenticate.SQRL.Client.Simple where

import Web.Authenticate.SQRL.Client
import Web.Authenticate.SQRL.SecureStorage



import qualified Crypto.Hash


-- | The version of this client.
simpleClientVersion :: Text
simpleClientVersion = "0.0.0.0"

-- | A 'TVar' containing the currently active user with a simplified encryption if the user has hinting allowed.
hinted :: TVar (Maybe (Text, SecureStorageBlock1))
hinted = newTVarIO Nothing


-- | Create a hash of the bytestring.
sha256hmac :: MasterIdentity -> ByteString -> ByteString
sha256hmac = f . Crypto.Hash.hmac
  where f :: Crypto.Hash.HMAC Crypto.Hash.SHA256 -> ByteString
        f = toBytes

-- | A simple client containing the current state.
data SimpleClient
  = SimpleClient
    { selectedProfile   :: Maybe SQRLProfile
    , masterIdentity    :: Maybe IdentityPrivateKey
    , previousIdentity  :: Maybe IdentityPrivateKey
    , masterLock        :: Maybe LockPrivateKey
    , clientKeys        :: HashMap Text (IdentityPrivateKey, Maybe IdentityPrivateKey, LockPrivateKey)
    }
  deriving (Eq)

instance Show SimpleClient where
  show (SimpleClient { selectedProfile = mp, masterIdentity = mi }) =
    "SimpleClient { selectedProfile = " ++ show mp ++ ", masterIdentity = " ++
    (case mi of { Nothing -> "Nothing" ; Just _ -> "Just <hidden-data>" }) ++
    " }"

-- | The 'SimpleClient' is a SQRL client.
instance SQRLClientM SimpleClient IO where
  sqrlClientName _ = "Hasqrell Simple"
  sqrlClientAuthor _ = "Tim Lundqvist"
  sqrlClientContact _ = "@TimLuq"
  sqrlClientVersion _ = simpleClientVersion

  sqrlIdentityKey dom = sqrlClient $ \s -> case HashMap.lookup dom $ clientKeys s of
    Just (k, _, _) -> return (s, k)
    Nothing -> s `runClient` (loadKeys dom >> sqrlIdentityKey dom)
  sqrlIdentityKeyPrevious dom = sqrlClient $ \s -> case HashMap.lookup dom $ clientKeys s of
    Just (_, k, _) -> return (s, k)
    Nothing -> s `runClient` (loadKeys dom >> sqrlIdentityKeyPrevious dom)
  sqrlLockKey dom = sqrlClient $ \s -> case HashMap.lookup dom $ clientKeys s of
    Just (_, _, k) -> return (s, k)
    Nothing -> s `runClient` (loadKeys dom >> sqrlLockKey dom)

  sqrlClearHint  = sqrlClient $ const clearHint
  sqrlClearSensitive c = sqrlClient' $ \s -> return (s { masterIdentity = Nothing, clientKeys = HashMap.empty }, ())

-- | A monadic wraper which 'fail's when an error is defined in the 'SimpleClient' (via 'clientError').
sqrlClient_ :: SimpleClient -> (SimpleClient -> IO (SimpleClient, t)) -> SQRLClient SimpleClient IO t
sqrlClient_ s f = case errorMessage s of
  Just er -> fail er
  Nothing -> sqrlClient s f >>= \r@(s', _) -> case errorMessage s' of
    Nothing -> return r
    Just er -> fail er

-- | Generate keys for a specific domain and store in current session.
-- This may cause the monad to 'fail' if the decryption is unsuccessful or no profile is selected.
loadKeys :: Domain -> SQRLClient SimpleClient IO ()
loadKeys dom = sqrlClient_ $ \s -> flip (,) () <$> case selectedProfile s of
  Nothing -> s { clientError = Just NoSelectedProfile }
  Just pr -> do
    let name = profileName pr
    (s', imk, lmk, pmk) <- case masterIdentity s of
      Just imk' -> return (s, imk', masterLock s, previousMaster s)
      Nothing   -> do
        mh <- atomically $ readTVar hinted
        if isNothing mh || fst (fromJust mh) /= name
         then profileSecureStorage pr >>= \x -> case x of
           Left er -> return (s { clientError = SecureStorageError er }, empty256, empty256, empty256)
           Right r -> decryptWith (password name $ secureStorageData1 r) >>= decrResult s
         else decryptWith (passwordHint name $ snd $ fromJust mh) >>= decrResult s
    return $ if isJust $ clientError s' then s'
             else let dom' = TE.encodeUtf8 dom in s' { clientKeys = HashMap.insert dom (sha256hmac imk dom', sha256 lmk dom', flip sha256hmac dom' <$> pmk) (clientKeys s') }
  where decrResult s x1 = case x1 of
          Left er -> return (s { clientError = DecryptError er }, empty256, empty256, empty256)
          Right d -> let imk' = identityMasterKey d
                         lmk' = identityLockKey d
                         pmk' = previousUnlockKey d
                     in return (s { masterIdentity = Just imk', masterLock = Just lmk', previousUnlock = pmk' }, imk', lmk', pmk')


-- | As with 'getLine' but with password. The integer parameter is a strength modifier which, if a natural number defines the strength of the password.
getPassword :: Int         -- ^ password stength modifier (negative disables, 0 normal, higher values makes it more difficult)
            -> IO String
getPassword b = bracket (hGetEcho stdin) (hSetEcho stdin) $ const $
  hSetEcho stdin False >> getLine >>= \p -> return p <* putStrLn $ if b >= 0 then "< " ++ show (passwordStrength b p) ++ " >" else ""

-- | Quick approximation of password quality.
passwordStrength :: Int -> String -> PasswordStrength
passwordStrength pw pass'
  | points < 2 * pw + 10   = BadPassword
  | points < 2 * pw + 32   = WeakPassword
  | points < 2 * pw + 64   = MediumPassword
  | points < 2 * pw + 128  = GoodPassword
  | otherwise              = StrongPassword
  where pass = take 200 pass'
        passl = length pass
        countGroups x f = case span f x of
          ("", ""  ) -> 0
          ("", _:x') -> countGroups x' f
          (_,  ""  ) -> 1
          (_,  _:x') -> 1 + countGroups x' f
        countConsec x s f = case span f x of
          ("", ""  ) -> []
          ("", _:x') -> countConsec x' f
          (r,  ""  ) -> if s r then [r] else []
          (r,  _:x') -> if s r then r : countConsec x' s f else countConsec x' s f
        points = sum
          [ 2 * length $ take 12 pass
          , 3 * length $ take 6 $ drop 12 pass
          , 4 * length $ drop 18 pass
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
clearHint = atomically $ writeTVar hinted Nothing


-- | This client uses 'SecureStorage' for it's profile management.
instance SecureStorageProfile SimpleClient IO where
  sspShowProfiles mf ps = let ps_ = sortBy (compare `on` profileUsed) ps in do
    hntd <- atomically $ readTVar hinted
    putStrLn ""
    ps' <- foldl (\(c, l) x -> (c+1, (' ' : show c ++ " ", x) : l)) (1, []) <$> case hntd of
      Nothing -> return $ take 8 ps_
      Just (nm, _, _) -> putStr " 9 " >> T.putStrLn nm >> putStrLn "" >> return $ take 8 $ filter ((/=) nm . profileName) ps_
    forM_ ps' $ \(n, p) -> putStr n >> T.putStrLn (profileName p) >> putStr "    last used: " >> putStrLn $ show $ profileUsed p
    putStrLn ""
    putStrLn " 0 - Create new profile"
    putStrLn ""
    putStr "Choice or search"
    when (fromMaybe T.empty mf /= T.empty) (putStr " for " >> T.putStr (fromJust mf))
    putStr ": "
    flush
    r <- getLine
    case r of
     "0" -> createProfileSimple
     [x] -> if x > '0' && x <= head (show $ length ps')
               then chooseProfileSimple $ snd $ ps' !! (fromEnum x - fromEnum '1')
               else sspShowProfiles mf $ filter (T.isInfixOf (T.singleton x) . profileName) ps_
     _   -> sspShowProfiles mf $ filter (T.isInfixOf (T.pack r) . profileName) ps_
  sspCurrentProfile = selectedProfile
  sspCreateProfile pf cf rname rpass =
    let readString t d = putStr (concat $ (:) (' ':t) $ (if null d then id else (:) " [" . (:) d . (:) "]") [": "]) >> flush >> getLine >>= \l ->
          if null l then if null d then return d else readString t d else return l
        readIt :: String -> a -> (a -> Maybe String) -> IO a
        readIt t d vf = readString t (show d) >>= \l ->
          ( (readIO l >>= \a -> case a of { Nothing -> return a ; Just err -> putStrLn (" -- " ++ err) >> readIt t d vf })
            <|> (putStrLn " -- invalid input value" >> readIt t d vf)
          )
        trim = reverse . dropWhile (' ' ==) . reverse . dropWhile (' ' ==)
        readBool t d = readString t (if d then "True " else "False") >>= \x -> let x' = trim map toLower x in
          if x' `elem` ["t", "true", "yes", "y", "1"] then return True
          else if x' `elem` ["f", "false", "no", "n", "0"] then return False
               else putStrLn " -- invalid boolean input" >> readBool t d
    in do putStrLn ""
          putStrLn "---- Creating a new profile ----"
          putStrLn ""
          name <- readString "Profile name" rname
          pass <- readString "Password" rpass
          hntl <- readIt "Password hint length" 4 $ \x ->
            if x < 3 then Just "Hint must be at least 3 characters long"
            else if x >= length pass then Just "Hint must be shorter than the password"
                 else Nothing
          hntt <- readIt "Password hint timeout (minutes)" 45 $ const Nothing
          pwht <- readIt "Password hashing time (seconds)" 10 $ \x ->
            if x < 10 then Just "With a short hashing time a brute force attack may be possible."
            else Nothing
          -- get client flags
          putStrLn ""
          putStrLn "---- Profile settings ----"
          putStrLn ""
          flgs <- mapM (\(f, d, t) -> readBool t d >>= \r -> if r then f else 0)
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
          r <- pf showCreationProgress (return BS.empty) name pass hntl hntt pwht flgs
          putStrLn ""
          case r of
           Left err -> putStrLn " -- Profile creation failed:" >> putStrLn (unlines $ map ((:) ' ' . (:) ' ' . (:) ' ' . (:) ' ') $ lines $ show err) >> putStrLn " -- Press enter to continue" >> getLine
           Right (prof, rcode) -> do
             putStrLn "---- Profile complete ----"
             putStrLn ""
             putStr   " Rescue code: " >> T.putStrLn rcode
             putStrLn ""
             putStrLn " Write the above series of numbers on a note and store it securly."
             putStrLn " The rescue code is the only way of rekeying, and thereby regaining control, of all accounts if your master key has fallen into someone elses possession."
             putStrLn " If possible write half the numbers on one note and store it securly at home and the other half on another note and store one copy in your wallet and the other in a vault at a bank."
             putStrLn ""
             putStrLn " -- Press enter after writing down the rescue code."
             getLine 
             cf emptyClient { selectedProfile = Just prof }
       

