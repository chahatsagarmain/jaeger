deploy_k8s_resources() {
  echo "Deploying HotROD and Jaeger to Kubernetes..."
  kustomize build /examples/hotrod/kubernetes | kubectl apply -f -

  # Wait for services to be ready
  kubectl wait --for=condition=available --timeout=180s deployment/example-hotrod -n example-hotrod
  kubectl wait --for=condition=available --timeout=180s deployment/jaeger -n example-hotrod

  # Port-forward HotROD and Jaeger services for local access
  kubectl port-forward -n example-hotrod svc/example-hotrod 8080:frontend &
  HOTROD_PORT_FWD_PID=$!
  kubectl port-forward -n example-hotrod svc/jaeger 16686:frontend &
  JAEGER_PORT_FWD_PID=$!
}

# Function to run the Kubernetes integration test
run_k8s_integration_test() {
  echo "Running Kubernetes integration tests..."
  if ! make all-in-one-integration-test ; then
      echo "---- Kubernetes integration test failed unexpectedly ----"
      echo "--- Fetching Jaeger logs ---"
      kubectl logs -l app=jaeger -n example-hotrod
      echo "--- Fetching HotROD logs ---"
      kubectl logs -l app=example-hotrod -n example-hotrod
      return 1  
  fi
  return 0  # Success
}

# Function to clean up the deployed resources
cleanup_k8s_resources() {
  echo "Cleaning up resources..."
  kill $HOTROD_PORT_FWD_PID
  kill $JAEGER_PORT_FWD_PID
  kustomize build /examples/hotrod/kubernetes | kubectl delete -f -
}