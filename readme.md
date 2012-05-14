About the MongoDB Session Bundle
================================
The MongoDB Session Bundle was created to be a drop in replacement for the [SQL Session Bundle](/EvolutionSDK/session). In fact it is more or less the same code except that this uses the [MongoDB Bundle](/KellyLSB/E3-Mongo-DB-Bundle) the store the sessions and hits. If you already use SQL Sessions all you need to do is install the MongoDB Bundle and delete the SQL Session bundle and clone this one in to replace it via. `git clone git@github.com:KellyLSB/E3-Mongo-Session-Bundle.git ./session`

Dependencies
============
- [MongoDB Bundle](/KellyLSB/E3-Mongo-DB-Bundle)