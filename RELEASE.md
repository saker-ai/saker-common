# Release Process

1. Run tests in the common module:

   ```bash
   GOWORK=off go test ./...
   ```

2. Commit the common module changes.

3. Create a semantic version tag:

   ```bash
   git tag v0.1.1
   ```

4. Push the branch and tag:

   ```bash
   git push origin main
   git push origin v0.1.1
   ```

5. Update consumers:

   ```bash
   go get github.com/saker-ai/saker-common@v0.1.1
   go mod tidy
   go test ./...
   ```

Use patch versions for compatible fixes and documentation updates. Use minor
versions for new compatible APIs. Reserve major versions for import path or API
breaks.
