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

newtype PrivateKey = PrivKey ByteString
type MasterKey = PrivateKey
type PrivateUnlockKey = PrivateKey


type SQRLClientIO clnt = SQRLClient clnt IO => clnt

newtype SQRLClientM clnt m => SQRLClient clnt m t = SQRLClient (clnt -> m (clnt, t))

instance Monad SQRLClient where
  return = SQRLClient . (,) s
  (SQRLClient xf) >>= (SQRLClient fy) = SQRLClient

sqrlClient :: (clnt -> m (clnt, t)) -> SQRLClient clnt m t
sqrlClient = SQRLClient

sqrlClient' :: (clnt -> m t) -> SQRLClient clnt m t
sqrlClient' f = SQRLClient $ \clnt -> (clnt, f clnt)

runClient :: clnt -> SQRLClient clnt m t
runClient clnt (SQRLClient f) = f clnt

class Monad m => SQRLClientM clnt m where
  sqrlClientName :: clnt -> Text
  sqrlClientVersion :: clnt -> Text
  sqrlVersion :: clnt -> SQRLVersion
  sqrlVersion _ = sqrlVersion1
  sqrlUnlockPublic :: SQRLClient clnt m (Maybe UnlockKey)
  default sqrlUnlockPublic :: MonadIO io => SQRLClient clnt io (Maybe UnlockKey)
  sqrlUnlockPublic = sqrlUnlockPub'
  sqrlUnlockPair :: SQRLClient clnt m (Maybe (PrivateUnlockKey, UnlockKey))
  default sqrlUnlockPair :: MonadIO io => SQRLClient clnt io (Maybe (PrivateUnlockKey, UnlockKey))
  sqrlUnlockPair = sqrlUnlockPair'
  sqrlMasterKey :: SQRLClient clnt m (Maybe MasterKey)
  default sqrlMasterKey :: MonadIO io => SQRLClient clnt io (Maybe MasterKey)
  sqrlMasterKey = sqrlMasterKey'
  sqrlChooseUser :: SQRLClient clnt m Bool
  default sqrlChooseUser :: MonadIO io => SQRLClient clnt io SQRLSecureStorage
  sqrlChooseUser = sqrlChooseUser'
  sqrlUserPassword :: SQRLClient clnt m (Maybe (Text, PasswordHash))
  sqrlUserName :: SQRLClient clnt m (Maybe Text)
  sqrlUserCreate :: Text -> Password -> SQRLClient clnt m (Either String PrivateUnlockKey)

sqrlUnlockPub' :: (MonadIO io, SQRLClientM clnt io) => clnt -> io (Maybe UnlockKey)
sqrlUnlockPub' client = do
  muser <- sqrlUserName client
  case muser of
   Nothing -> return Nothing
   Just user -> liftIO $ let keyfile = (++) "sqrl-client-nut-" $ B64U.encode $ TE.encodeUtf8 user
    catchIOError (pad16'8 <$> BS.readFile $  "sqrl-client-nut-key.dat") $ \e -> do
      when (isPermissionError e) $ putStrLn "sqrl-nut-key.dat is not accessible due to permissions. Generating a temporary key."
             else "sqrl-nut-key.dat can not be read because of some unknown error (" ++ show e ++ "). Generating a temporary key."
      g <- newGenIO
      rand <- genBytes 16 (g :: SystemRandom)
      modifyMVar sqrlCounter $ \(i, g) -> case (\(x, g') -> ((i, g'), x)) <$> genBytes 16 g of
        Left err -> fail $ "sqrlIV': default key could not be created: " ++ show err
        Right r' -> return r'
