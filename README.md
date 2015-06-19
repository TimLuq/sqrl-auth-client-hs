# sqrl-auth-client-hs
Back-end client for SQRL in Haskell. A library without any ambition for a GUI but instead focuses on extendability.

Other more usable clients (what some call "user friendly") could use this as the core and, as such, be released from most of the responsability for the SQRL protocol and the key generation. It will have a nice, easy-to-use, class which may be instantiated and - if it should act in the `IO` monad or any `MonadIO m` - most of the default class functions should be able to be used. They are there to allow for some more exotic monads and to be able to customize the user experience as one sees fit.

The creation of this package is due to the need for a slim command line client and a client library for targeted tests of *sqrl-auth-hs*; which is the server equivalent of this client project.

## sqrl-auth-hs
The *sqrl-auth-hs* package is primarily for server implementations and provides support for the protocol and common usage. The client package reuses and reexports much of the same structures and functions as the server package. The server package is therefore a dependency.

# SQRL
SQRL is a cryptographic authentication system to be used instead of a common password login. It supports cross-device login as well as same-device login.

