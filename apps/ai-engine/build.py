"""Build the private native provider extensions against one immutable upstream tree.

Usage: python3 build.py SOURCE_GIT_DIRECTORY OUTPUT_BINARY
The source checkout is read-only; builds use a fresh temporary archive.
"""
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile

PIN = "9537b2fadf42af90eb34ed47d3d4252e1beff4a0"
source, output = map(pathlib.Path, sys.argv[1:3])
run_tests = "--test" in sys.argv[3:]
extension = pathlib.Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="tunnex-saved-probe-") as scratch:
    root = pathlib.Path(scratch)
    archive = root / "source.tar"
    subprocess.run(["git", "-C", str(source), "archive", "--format=tar", "-o", str(archive), PIN], check=True)
    with tarfile.open(archive) as tar:
        tar.extractall(root, filter="data")
    handlers = root / "transports/bifrost-http/handlers"
    routes = handlers / "providers.go"
    marker = '\tr.GET("/api/keys", lib.ChainMiddlewares(h.listKeys, middlewares...))'
    text = routes.read_text()
    assert text.count(marker) == 1, "pinned route registration changed"
    routes.write_text(text.replace(marker,
        '\tr.POST("/api/providers/{provider}/keys/{key_id}/test-connection", lib.ChainMiddlewares(h.tunnexSavedKeyProbe, middlewares...))\n'
        '\tr.POST("/api/tunnex/test-connection", lib.ChainMiddlewares(h.tunnexDraftProbe, middlewares...))\n'
        '\tr.POST("/api/tunnex/model-catalog", lib.ChainMiddlewares(h.tunnexDraftCatalog, middlewares...))\n' + marker))
    (handlers / "tunnex_saved_probe.go").write_bytes((extension / "saved_probe.go").read_bytes())
    (handlers / "tunnex_native_operations.go").write_bytes((extension / "native_operations.go").read_bytes())
    native = root / "core/providers/tunnexsagemaker"
    native.mkdir()
    (native / "sagemaker.go").write_bytes((extension / "sagemaker.go").read_bytes())
    core = root / "core/bifrost.go"
    core_text = core.read_text()
    import_marker = '"github.com/maximhq/bifrost/core/providers/openai"'
    assert core_text.count(import_marker) == 1
    core_text = core_text.replace(import_marker, import_marker + '\n"github.com/maximhq/bifrost/core/providers/tunnexsagemaker"')
    case_marker = 'switch targetProviderKey {'
    assert core_text.count(case_marker) == 1
    core.write_text(core_text.replace(case_marker, case_marker + '\ncase schemas.ModelProvider("tnx-sagemaker"):\nreturn tunnexsagemaker.New(config, bifrost.logger)'))
    utils = root / "core/utils.go"
    utils_text = utils.read_text()
    supported = 'func IsSupportedBaseProvider(providerKey schemas.ModelProvider) bool {'
    assert utils_text.count(supported) == 1
    utils.write_text(utils_text.replace(supported, supported + '\nif providerKey == schemas.ModelProvider("tnx-sagemaker") { return true }'))
    # A transient private probe uses a strict upstream response bound. Zero is
    # unchanged serving behavior; the setting is internal and not JSON-exposed.
    schema_provider = root / "core/schemas/provider.go"
    schema_text = schema_provider.read_text()
    network_marker = "type NetworkConfig struct {"
    assert schema_text.count(network_marker) == 1
    schema_provider.write_text(schema_text.replace(network_marker, network_marker + '\nTunnexMaxResponseBodySize int `json:"-"`'))
    provider_types = {"openai":"OpenAIProvider", "anthropic":"AnthropicProvider", "gemini":"GeminiProvider", "openrouter":"OpenRouterProvider", "groq":"GroqProvider", "mistral":"MistralProvider", "cerebras":"CerebrasProvider", "xai":"XAIProvider", "deepseek":"DeepSeekProvider"}
    for name, kind in provider_types.items():
        file = root / f"core/providers/{name}/{name}.go"
        body = file.read_text()
        client_marker = "client := &fasthttp.Client{"
        assert body.count(client_marker) == 1, f"pinned {name} constructor changed"
        body = body.replace(client_marker, client_marker + '\nMaxResponseBodySize: config.NetworkConfig.TunnexMaxResponseBodySize,')
        body += f"\nfunc(provider *{kind}) TunnexCloseProbeConnections() {{ provider.client.CloseIdleConnections() }}\n"
        file.write_text(body)
    if run_tests:
        (native / "sagemaker_test.go").write_bytes((extension / "sagemaker_test.go").read_bytes())
        (handlers / "tunnex_native_operations_test.go").write_bytes((extension / "native_operations_test.go").read_bytes())
    lib = root / "transports/bifrost-http/lib"
    (lib / "tunnex_sagemaker_migration.go").write_bytes((extension / "sagemaker_migration.go").read_bytes())
    lib_config = lib / "config.go"
    config_text = lib_config.read_text()
    immutable = 'if newCPC.BaseProviderType != existingCPC.BaseProviderType {'
    assert config_text.count(immutable) == 1
    lib_config.write_text(config_text.replace(immutable, immutable + '\nif tunnexSageMakerMigration(newConfig, existingConfig, provider) { return ValidateCustomProvider(newConfig, provider) }'))
    # Compile the extended core from this immutable archive, rather than the
    # published module (which intentionally lacks the Tunnex provider package).
    transport_module = root / "transports/go.mod"
    transport_module.write_text(transport_module.read_text() + '\nreplace github.com/maximhq/bifrost/core => ../core\n')
    # The private engine has no customer dashboard; Tunnex supplies its own UI.
    ui = root / "transports/bifrost-http/ui"
    ui.mkdir(exist_ok=True)
    (ui / "index.html").write_text("Private Tunnex AI engine")
    env = dict(os.environ, GOWORK="off", GOFLAGS="-mod=readonly")
    if run_tests:
        subprocess.run(["go", "test", "./providers/tunnexsagemaker", "-run", "^TestTunnex", "-count=1"], cwd=root / "core", env=env, check=True)
        subprocess.run(["go", "test", "./bifrost-http/handlers", "-run", "^TestTunnex", "-count=1"], cwd=root / "transports", env=env, check=True)
    subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w -X main.Version=v2.0.0-tunnex-native.1", "-o", str(output.resolve()), "./bifrost-http"], cwd=root / "transports", env=env, check=True)

    if run_tests:
        subprocess.run([sys.executable, str(extension / "native_transport_test.py"), str(output.resolve())], env=env, check=True)
