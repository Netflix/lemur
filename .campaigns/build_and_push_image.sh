#!/bin/bash
set -eo pipefail

# The user that clones the repository (root) is different from the user performing git commands
git config --global --add safe.directory /go/src/github.com/DataDog/lemur

# Determine the specific commit to build an image for
IMAGE_TAG=$(echo $GBILITE_IMAGE_TO_BUILD | cut -d ':' -f 2)
BASE_IMAGE=registry.ddbuild.io/images/base/gbi-ubuntu_2204:release
FIPS_ENABLED=false
if [[ $GBILITE_IMAGE_TO_BUILD == *"-fips" ]]; then
  BASE_IMAGE=registry.ddbuild.io/images/base/gbi-ubuntu_2204-fips:release
  FIPS_ENABLED=true
fi

CHECKOUT_REF=${CHECKOUT_REF:-$(git rev-parse HEAD)}

# Build and sign the image
cd publish/
METADATA_FILE=$(mktemp)
docker buildx build \
  --label target=$GBILITE_ENV \
  --build-arg CI_COMMIT_SHA=$CHECKOUT_REF \
  --build-arg BASE_IMAGE=$BASE_IMAGE \
  --build-arg FIPS_ENABLED=$FIPS_ENABLED \
  --build-arg GBILITE_ENV=$GBILITE_ENV \
  --build-arg CI_PIPELINE_ID=$CI_PIPELINE_ID \
  --build-arg IMAGE_TAG=$IMAGE_TAG \
  --tag registry.ddbuild.io/$GBILITE_IMAGE_TO_BUILD \
  --metadata-file ${METADATA_FILE} \
  --push \
  .
ddsign sign registry.ddbuild.io/$GBILITE_IMAGE_TO_BUILD --docker-metadata-file ${METADATA_FILE}

# Tag as mutable-latest only from master-commit builds.
if [[ "$CI_COMMIT_BRANCH" == "master" && $GBILITE_ENV == "prod" && $FIPS_ENABLED == "false" ]]; then
  crane tag registry.ddbuild.io/$GBILITE_IMAGE_TO_BUILD mutable-latest-prod
elif [[ "$CI_COMMIT_BRANCH" == "master" && $GBILITE_ENV == "prod" && $FIPS_ENABLED == "true" ]]; then
  crane tag registry.ddbuild.io/$GBILITE_IMAGE_TO_BUILD mutable-latest-prod-fips
fi

cd ../
IMAGE_DIGEST=$(crane digest registry.ddbuild.io/$GBILITE_IMAGE_TO_BUILD)

# Output image metadata (required by campaigner)
echo $IMAGE_TAG > .campaigns/image_info.txt
echo $IMAGE_DIGEST >> .campaigns/image_info.txt

echo ""
echo "================================================================"
echo "Pushed image:  registry.ddbuild.io/lemur:$IMAGE_TAG"
echo "Image tag:     $IMAGE_TAG"
echo "Image digest:  $IMAGE_DIGEST"
echo "================================================================"
