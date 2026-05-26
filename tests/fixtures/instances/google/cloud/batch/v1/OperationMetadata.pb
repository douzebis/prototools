#@ prototext: protoc
create_time {  #@ Timestamp = 1
  seconds: 1710498600  #@ int64 = 1
}
end_time {  #@ Timestamp = 2
  seconds: 1710502200  #@ int64 = 1
}
target: "projects/my-project/locations/europe-west1/jobs/my-batch-job"  #@ string = 3
verb: "create"  #@ string = 4
status_message: "Job completed successfully."  #@ string = 5
api_version: "v1"  #@ string = 7
