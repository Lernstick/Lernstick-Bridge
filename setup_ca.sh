#!/bin/bash
# Run the necessary steps to setup the cv_ca without the running the verifier first

IMAGE="ghcr.io/ths-on/keylime/keylime_verifier"

echo "Use default as password or change it in the keylime.conf"

docker run -v $(pwd)/cv_ca:/cv_ca  --entrypoint "/bin/bash" -it --rm $IMAGE -c "keylime_ca -d /cv_ca -c init -n init"
docker run -v $(pwd)/cv_ca:/cv_ca  --entrypoint "/bin/bash" -it --rm $IMAGE -c "keylime_ca -d /cv_ca -c create -n client"
docker run -v $(pwd)/cv_ca:/cv_ca  --entrypoint "/bin/bash" -it --rm $IMAGE -c "keylime_ca -d /cv_ca -c create -n server"