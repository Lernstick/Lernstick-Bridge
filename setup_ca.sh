#!/bin/bash
# Run the necessary steps to setup the cv_ca without the running the verifier first

IMAGE="quay.io/keylime/keylime_base"

echo "Use \"default\" as password or change it in the keylime.conf"

docker run \
  -v $(pwd)/cv_ca:/cv_ca  \
  -v $(pwd)/setup_ca.py:/setup_ca.py \
  -v $(pwd)/keylime.conf.d:/etc/keylime \
  --entrypoint "/setup_ca.py" -it --rm $IMAGE
