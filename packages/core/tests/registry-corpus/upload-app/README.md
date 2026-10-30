# upload-app

Deliberately unsafe upload handling for the registry integrity test: multer and
express-fileupload without limits or type checks, a stored name taken from the client, and a server
action writing `file.name` as an S3 key. `multer ^2.0.0` with no lockfile keeps the disk-name finding
at medium/high. Do not "fix" the samples.
