#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"

#Version number that updates chart and images
CHART_VERSION="0.3.4"
APP_VERSION="0.3.4"
POD_SCANNER_REPOSITORY="bjornvb/k8s-pod-scanner"
VULNERABILITY_COORDINATOR_REPOSITORY="bjornvb/k8s-scanner-vulnerability-coordinator"
WEB_FRONTEND_REPOSITORY="bjornvb/k8s-scanner-web-frontend"

echo Generate release $APP_VERSION
./doreleasecontainer.sh "$POD_SCANNER_REPOSITORY:$APP_VERSION" "pod-scanner"
./doreleasecontainer.sh "$VULNERABILITY_COORDINATOR_REPOSITORY:$APP_VERSION" "vulnerability-coordinator"
./doreleasecontainer.sh "$WEB_FRONTEND_REPOSITORY:$APP_VERSION" "web-frontend"

cat bjorn2scan/values.yaml | yq eval ".podScanner.image.tag = \"${APP_VERSION}\" | 
                                            .vulnerabilityCoordinator.image.tag = \"${APP_VERSION}\" 
                                            | .webFrontend.image.tag = \"${APP_VERSION}\"" > bjorn2scan/newvalues.yaml
mv bjorn2scan/newvalues.yaml bjorn2scan/values.yaml

cat bjorn2scan/Chart.yaml | yq eval ".appVersion=\"${APP_VERSION}\""  | yq eval ".version=\"${CHART_VERSION}\"" > bjorn2scan/newChart.yaml
mv bjorn2scan/newChart.yaml bjorn2scan/Chart.yaml

echo Publish Helm chart
CHART_FILE_NAME="bjorn2scan-${CHART_VERSION}.tgz"
helm package bjorn2scan
echo "Chart filename: $CHART_FILE_NAME"
helm push ${CHART_FILE_NAME} oci://registry-1.docker.io/bjornvb
rm ${CHART_FILE_NAME}

echo Complete and generated the following containers:
echo "$POD_SCANNER_REPOSITORY:$APP_VERSION"
echo "$VULNERABILITY_COORDINATOR_REPOSITORY:$APP_VERSION"
echo "$WEB_FRONTEND_REPOSITORY:$APP_VERSION"
echo "registry-1.docker.io/bjornvb/${CHART_FILE_NAME}"
