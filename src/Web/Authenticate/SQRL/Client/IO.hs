{-# LANGUAGE OverloadedStrings #-}
module Web.Authenticate.SQRL.Client.IO (module Web.Authenticate.SQRL.Client.IO, withSocketsDo) where


import Web.Authenticate.SQRL.Types
import Web.Authenticate.SQRL.Client as C
import Web.Authenticate.SQRL.Client.Types

import Data.Word (Word8)
import Network.HTTP.Types.Header
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Control.Monad.IO.Class (MonadIO, liftIO)
--import qualified Data.Conduit as C
--import Network.HTTP.Conduit
import Network.Socket (withSocketsDo)
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
--import qualified Data.ByteString.Base64.URL as B64U
import Control.Applicative
--import Data.Binary
import Data.Bits
import System.IO as IO
import qualified System.Info

import System.IO.Unsafe (unsafePerformIO)

import Control.Exception (IOException)
import Control.Monad.Catch (MonadCatch, throwM, handle)
import Control.Concurrent.MVar

data SQRLRequest = SQRLRequest { sqrlRequest :: Request, sqrlRequestPost :: SQRLClientPost ByteString, sqrlRequestURL :: SQRLUrl } deriving (Show)
type SQRLClientRequest clnt m t = SQRLRequest -> SQRLClient clnt m (SQRLRequest, t)

modifySQRLRequest :: (SQRLClientPost ByteString -> SQRLClientPost ByteString) -> SQRLRequest -> SQRLRequest
modifySQRLRequest f s =
  let (p, bs) = sqrlClientPostBytes (f (sqrlRequestPost s))
      s0 = (sqrlRequest s) { requestBody = RequestBodyLBS bs }
  in s { sqrlRequest = s0, sqrlRequestPost = p }

modifySQRLRequest' :: (Functor m, Monad m) => (SQRLClientPost ByteString -> m (SQRLClientPost ByteString)) -> SQRLRequest -> m SQRLRequest
modifySQRLRequest' f s = do
  (p, bs) <- sqrlClientPostBytes <$> f (sqrlRequestPost s)
  let s0 = (sqrlRequest s) { requestBody = RequestBodyLBS bs }
    in return s { sqrlRequest = s0, sqrlRequestPost = p }


-- | Switches the protocol from SQRL to HTTP.
sqrlUrlToHttp :: SQRLUrl -> String
sqrlUrlToHttp (SQRLUrl sec dom rlm pth qry)
  = concat [ if sec then "https://" else "http://"
           , T.unpack dom , "/", T.unpack rlm
           , T.unpack pth, "?", T.unpack qry
           ]

-- | Like unzip, but for maybe.
mayzip :: Maybe (a, b) -> (Maybe a, Maybe b)
mayzip Nothing = (Nothing, Nothing)
mayzip (Just (a, b)) = (Just a, Just b)

-- | Update 'SQRLClientData'.
updateClientData :: (MonadIO m, SQRLClientM clnt m) => SQRLCommandAction -> SQRLRequest -> SQRLClient clnt m SQRLRequest
updateClientData action req@SQRLRequest { sqrlRequestURL = url } = do
  liftIO $ putStrLn $ "TRACE: updateClientData: updating " ++ show url ++ "..."
  s <- getClientState
  (serverunlockkey, verifyunlockkey) <- case action of
    IDENT -> case sqrlServerData $ sqrlRequestPost req of
      Left  _ -> return (Nothing, Nothing)
      Right r -> if (serverTransFlags r .&. tifCurrentIDMatch) == tifCurrentIDMatch
                 then return (Nothing, Nothing)
                 else (\(a, b) -> (Just a, Just b)) <$> generateUnlockKeys
    _ -> return (Nothing, Nothing)
  req' <- flip modifySQRLRequest' req $ \post -> sqrlSignPost url $
          modifySQRLClientData (\cdata -> cdata { clientVersion = C.sqrlVersion s, clientCommand = action, clientServerUnlock = serverunlockkey, clientVerifyUnlock = verifyunlockkey }) post
  liftIO $ putStrLn "TRACE: updateClientData: signed."
  return req'

-- | Execute a 'SQRLCommandAction' on a 'SQRLRequest'.
sqrlExecuteCommand :: (MonadCatch m, MonadIO m, SQRLClientM clnt m) => SQRLCommandAction -> Manager -> SQRLClientRequest clnt m (SQRLServerData ByteString)
sqrlExecuteCommand action manager req = handle (\e -> throwM (e :: IOException)) $ do
  liftIO $ putStrLn $ "TRACE: sqrlExecuteCommand: executing " ++ show action ++ "..."
  req' <- updateClientData action req
  sdata0 <- doExecute req'
  if (serverTransFlags (snd sdata0) .&. tifTransientError) /= tifTransientError
    then return sdata0
    else doExecute (fst sdata0)
  where communicate req' = do
          IO.withBinaryFile "/tmp/sqrl-last-server-request.dat" IO.WriteMode $ \h -> LBS.hPut h (let RequestBodyLBS rb = requestBody (sqrlRequest req') in rb) >> hPutStr h ("\n\n" ++ show req')
          httpLbs (sqrlRequest req') manager
        qmrk = fromIntegral (fromEnum '?') :: Word8
        doExecute req' = do
          resp <- liftIO $ communicate req'
          liftIO $ putStrLn "TRACE: sqrlExecuteCommand: response gathered..."
          let bodys = LBS.toStrict $ responseBody resp
          liftIO $ IO.withBinaryFile "/tmp/sqrl-last-server-response.dat" IO.WriteMode $ \h -> BS.hPut h bodys
          let sdata = (readSQRLServerData BS.empty BS.empty bodys :: Either String (SQRLServerData ByteString))
              pall  = ("server", bodys) : sqrlPostAll (sqrlRequestPost req)
            in case sdata of
                Left err -> fail err
                Right sdata' -> do
                  liftIO $ putStrLn $ "TRACE: sqrlExecuteCommand: done executing " ++ show action ++ "."
                  liftIO $ IO.withBinaryFile "/tmp/sqrl-last-server-response.dat" IO.AppendMode $ \h -> hPutStr h ("\n\n" ++ show sdata')
                  return (req' { sqrlRequestPost = (sqrlRequestPost req') { sqrlServerData = Right sdata', sqrlPostAll = pall }
                               , sqrlRequest = let (path', query') = BS.breakByte qmrk (TE.encodeUtf8 $ serverQueryPath sdata') in (sqrlRequest req') { path = path', queryString = query' }
                               }, sdata')


-- | A temporary 'SQRLClientPost'. 'sqrlClientData' and 'sqrlSignatures' MUST be overwritten ASAP.
defpostdata :: SQRLUrl -> SQRLClientPost ByteString
defpostdata url = SQRLClientPost
          { sqrlServerData = Left url
          , sqrlClientData = error "Client data not overridden."
          , sqrlSignatures = SQRLSignatures
                             { signIdentity   = error "Identity signature not overridden."
                             , signPreviousID = error "Previous signature not overridden."
                             , signUnlock     = error "Unlock signature not overridden."
                             }
          , sqrlPostAll    = [("server", enc64unpad $ sqrlUrlToBS url)]
          }

-- | TODO: Placeholder for transferring account association.
sqrlUpdateToCurrentID :: (MonadIO m, SQRLClientM clnt m) => SQRLRequest -> SQRLClient clnt m SQRLRequest
sqrlUpdateToCurrentID = return

-- | Placeholder for any special handeling during account association.
sqrlAssociateAccount :: (MonadIO m, SQRLClientM clnt m) => SQRLRequest -> SQRLClient clnt m SQRLRequest
sqrlAssociateAccount = return


{-# NOINLINE managerVar #-}
managerVar :: MVar (Maybe Manager)
managerVar = unsafePerformIO $ newMVar Nothing

wManager :: (MonadIO m) => m Manager
wManager = liftIO $ modifyMVar managerVar $ \mman -> case mman of
    Just man' -> return (mman, man')
    Nothing   -> (\x -> (Just x, x)) <$> newManager (managerSetInsecureProxy (useProxy (Proxy "localhost" 23889)) tlsManagerSettings)

-- | Connect the client to a host.
sqrlConnect :: (MonadCatch m, MonadIO m, SQRLClientM clnt m) => SQRLUrl -> SQRLClient clnt m (SQRLRequest, SQRLServerData ByteString)
sqrlConnect url = do
  request <- parseUrl http
  wManager >>= \manager -> sqrlExecuteCommand QUERY manager (req request { requestHeaders = hdrs })
  where req request = SQRLRequest { sqrlRequest = request, sqrlRequestPost = defpostdata url, sqrlRequestURL = url }
        http = sqrlUrlToHttp url
        hdrs = [ (hUserAgent, "SQRL/1 (" ++ System.Info.os ++ "; " ++ System.Info.arch ++ ") hasqrell/" ++ thisVersion ++ " (cps; markdown)")
               , (hContentType, "application/x-www-urlencoded")
               ]

-- | Connect to a SQRL server and do the most common communication flow. These include:
-- # Query server for association.
-- # Update from previous identity, if any. (This differs from the spec where a user SHOULD be able to allow this and it is not implicitly done.)
-- # If no association; ask user if association should be made
-- # Let the user answer 'SQRLAsk' if sent by the server
-- # If no 'SQRLAsk' was sent; ask the user to allow the login/sign.
-- # Signing of the nut
--
-- Note: This may, or may not, fork to complete the connection flow. Any error (or completion) will be reported to the first parameter which is a callback.
sqrlConnectionFlow :: (MonadCatch m, MonadIO m, SQRLClientM clnt m) => (ClientErr -> SQRLClient clnt m ()) -> SQRLUrl -> SQRLClient clnt m ()
sqrlConnectionFlow real_callback url = callback <<|| do
  liftIO $ putStrLn $ "TRACE: sqrlConnectionFlow: starting connection flow to: " ++ show url
  request <- parseUrl http
  clientdef <- sqrlClientDataDefault
  wManager >>= \manager -> sqrlConnectFlow_0 callback manager (req_ (request { requestHeaders = [(hUserAgent, "SQRL/1"),(hContentType, "application/x-www-urlencoded")], method = "POST" }) clientdef) <||> callback
  where callback x =
          liftIO (putStrLn ("TRACE: ClientErr = " ++ show x)) >>
          real_callback x <|> setClientError ClientErrNone -- allow for non-forked user interactions to error handle correctly
        http = sqrlUrlToHttp url
        req_ request clientdef = SQRLRequest { sqrlRequest = request, sqrlRequestPost = (defpostdata url) { sqrlClientData = clientdef }, sqrlRequestURL = url }
        sqrlConnectFlow_0 :: (MonadCatch m, MonadIO m, SQRLClientM clnt m) => (ClientErr -> SQRLClient clnt m ()) -> Manager -> SQRLRequest -> SQRLClient clnt m ()
        sqrlConnectFlow_0 callback' manager req = do
          liftIO $ putStrLn "TRACE: sqrlConnectFlow_0: connection 0 commencing."
          (req', sdata) <- sqrlExecuteCommand QUERY manager req
          if (serverTransFlags sdata .&. tifCurrentIDMatch) /= tifEmpty
            then sqrlConnectFlow_1 callback' manager req'
            else if (serverTransFlags sdata .&. tifPreviousIDMatch) /= tifEmpty
                 then sqrlUpdateToCurrentID req' >>= \req'' -> sqrlConnectFlow_1 callback' manager req'' <||> callback'
                 else sqrlAccountAssociation ((sqrlAssociateAccount req' >>= \req'' -> sqrlConnectFlow_1 callback' manager req'') <||> callback') (callback' ClientErrAssocAborted) url sdata
        sqrlConnectFlow_1 :: (MonadCatch m, MonadIO m, SQRLClientM clnt m) => (ClientErr -> SQRLClient clnt m ()) -> Manager -> SQRLRequest -> SQRLClient clnt m ()
        sqrlConnectFlow_1 callback' manager (req@SQRLRequest { sqrlRequestPost = cp }) =
          let sdata = fromRight (sqrlServerData cp)
              processAsk x = sqrlConnectFlow_2 callback' manager (req { sqrlRequestPost = cp { sqrlClientData = (sqrlClientData cp) { clientAskResponse = Just x } } }) IDENT
          in do
            liftIO $ putStrLn "TRACE: sqrlConnectFlow_1: connection 1 commencing."
            case serverAsk sdata of
             Nothing -> sqrlLoginAccount (\x -> sqrlConnectFlow_2 callback' manager req x <||> callback') (callback' ClientErrLoginAborted) url sdata
             Just sk -> sqrlAskClient (\x -> processAsk x <||> callback') (callback' ClientErrAskAborted) sk url sdata
        sqrlConnectFlow_2 :: (MonadCatch m, MonadIO m, SQRLClientM clnt m) => (ClientErr -> SQRLClient clnt m ()) -> Manager -> SQRLRequest -> SQRLCommandAction -> SQRLClient clnt m ()
        sqrlConnectFlow_2 callback' manager req action = do
          liftIO $ putStrLn "TRACE: sqrlConnectFlow_2: connection 2 commencing."
          _ <- sqrlExecuteCommand action manager req
          callback' ClientErrNone
          liftIO $ putStrLn "TRACE: sqrlConnectionFlow: connection flow complete."
        fromRight (Right x) = x
        fromRight _ = error "fromRight: was left"
          
