#@ prototext: protoc
create_time {  #@ Timestamp = 1
  seconds: 1710502800  #@ int64 = 1
}
end_time {  #@ Timestamp = 2
  seconds: 1710503220  #@ int64 = 1
}
target: "projects/sec-audit/locations/europe-west1/functions/detect-anomalous-proto"  #@ string = 3
verb: "create"  #@ string = 4
status_detail: "Build succeeded. Deploying function to Cloud Run."  #@ string = 5
api_version: "v2"  #@ string = 7
source_token: "bf3a91c2-4d7e-4f1a-b8c3-9e0d5f2a6b4e"  #@ string = 10
build_name: "projects/sec-audit/locations/europe-west1/builds/a1b2c3d4"  #@ string = 13
operation_type: CREATE_FUNCTION  #@ OperationType(1) = 11
stages {  #@ repeated Stage = 9
  name: ARTIFACT_REGISTRY  #@ Name(1) = 1
  message: "Uploading source archive to Artifact Registry."  #@ string = 2
  state: COMPLETE  #@ State(3) = 3
  resource: "europe-west1-docker.pkg.dev/sec-audit/gcf-artifacts/detect-anomalous-proto"  #@ string = 4
}
stages {  #@ repeated Stage = 9
  name: BUILD  #@ Name(2) = 1
  message: "Building container image from source."  #@ string = 2
  state: COMPLETE  #@ State(3) = 3
  resource: "projects/sec-audit/locations/europe-west1/builds/a1b2c3d4"  #@ string = 4
}
stages {  #@ repeated Stage = 9
  name: SERVICE  #@ Name(3) = 1
  message: "Deploying container to Cloud Run."  #@ string = 2
  state: IN_PROGRESS  #@ State(2) = 3
  resource: "projects/sec-audit/locations/europe-west1/services/detect-anomalous-proto"  #@ string = 4
}
