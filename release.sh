#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"

#Version number that updates chart and images
CHART_VERSION="0.2.06"
APP_VERSION="0.2.06"
POD_SCANNER_REPOSITORY="bjornvb/k8s-pod-scanner"
VULNERABILITY_COORDINATOR_REPOSITORY="bjornvb/k8s-scanner-vulnerability-coordinator"
WEB_FRONTEND_REPOSITORY="bjornvb/k8s-scanner-web-frontend"

echo Generate release $APP_VERSION
./doreleasecontainer.sh "$POD_SCANNER_REPOSITORY:$APP_VERSION" "pod-scanner"
./doreleasecontainer.sh "$VULNERABILITY_COORDINATOR_REPOSITORY:$APP_VERSION" "vulnerability-coordinator"
./doreleasecontainer.sh "$WEB_FRONTEND_REPOSITORY:$APP_VERSION" "web-frontend"

cat k8s-vuln-scanner/values.yaml | yq eval ".podScanner.image.tag = \"${APP_VERSION}\" | 
                                            .vulnerabilityCoordinator.image.tag = \"${APP_VERSION}\" 
                                            | .webFrontend.image.tag = \"${APP_VERSION}\"" > k8s-vuln-scanner/newvalues.yaml
mv k8s-vuln-scanner/newvalues.yaml k8s-vuln-scanner/values.yaml

cat k8s-vuln-scanner/Chart.yaml | yq eval ".appVersion=\"${APP_VERSION}\""  | yq eval ".version=\"${CHART_VERSION}\"" > k8s-vuln-scanner/newChart.yaml
mv k8s-vuln-scanner/newChart.yaml k8s-vuln-scanner/Chart.yaml

echo Complete and generated the following containers:
echo "$POD_SCANNER_REPOSITORY:$APP_VERSION"
echo "$VULNERABILITY_COORDINATOR_REPOSITORY:$APP_VERSION"
echo "$WEB_FRONTEND_REPOSITORY:$APP_VERSION"
