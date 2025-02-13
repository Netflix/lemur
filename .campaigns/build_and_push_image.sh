#!/bin/bash
set -eo pipefail

# The user that clones the repository (root) is different from the user performing git commands
git config --global --add safe.directory /go/src/github.com/DataDog/lemur

# Determine the specific commit or release to build an image for
IMAGE_TAG=$(echo $GBILITE_IMAGE_TO_BUILD | cut -d ':' -f 2)
BASE_IMAGE=registry.ddbuild.io/images/base/gbi-ubuntu_2204:release
FIPS_ENABLED=false
if [[ $GBILITE_IMAGE_TO_BUILD == "lemur:latest" ]]; then
  LATEST_RELEASE_TAG=$(git describe --tags $(git rev-list --tags --max-count=1))
  CHECKOUT_REF=$LATEST_RELEASE_TAG
elif [[ $GBILITE_IMAGE_TO_BUILD == *"-fips" ]]; then
  BASE_IMAGE=registry.ddbuild.io/images/base/gbi-ubuntu_2204-fips:release
  FIPS_ENABLED=true
fi

if [[ -z "$CHECKOUT_REF" ]]; then
  CHECKOUT_REF=$IMAGE_TAG
fi

# Build and sign the image
cd publish/
METADATA_FILE=$(mktemp)
docker buildx build \
  --label target=$GBILITE_ENV \
  --build-arg CI_COMMIT_SHA=$CHECKOUT_REF \
  --build-arg BASE_IMAGE=$BASE_IMAGE \
  --build-arg FIPS_ENABLED=$FIPS_ENABLED \
  --tag registry.ddbuild.io/$GBILITE_IMAGE_TO_BUILD \
  --metadata-file ${METADATA_FILE} \
  --push \
  .
ddsign sign registry.ddbuild.io/$GBILITE_IMAGE_TO_BUILD --docker-metadata-file ${METADATA_FILE}

# Output image metadata (required by campaigner)
cd ../
echo $IMAGE_TAG > .campaigns/image_info.txt
echo $(crane digest registry.ddbuild.io/$GBILITE_IMAGE_TO_BUILD) >> .campaigns/image_info.txt
