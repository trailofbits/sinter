import Dispatch

func main() {
  if let auth_manager = AuthorizationManager() {
    auth_manager.exec()

  } else {
    print("Failed to initialize the EndpointSecurityClient object");
  }
}

main()
