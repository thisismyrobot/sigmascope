import pytest
import yaml

import sigmascope


def test_load_valid_backend():
    sigmascope.load_backend(
        ("sigma.backends.splunk", "SplunkBackend"),
        ("sigma.pipelines.splunk", "splunk_windows_pipeline"),
    )


def test_invalid_pipeline_module_throws_exception():
    with pytest.raises(
        ValueError,
        match="Pipeline module sigma.pipelines.foo_pipeline could not be imported",
    ):
        sigmascope.load_backend(
            ("sigma.backends.splunk", "SplunkBackend"),
            ("sigma.pipelines.foo_pipeline", "splunk_windows_pipeline"),
        )


def test_invalid_pipeline_factory_throws_exception():
    with pytest.raises(
        ValueError,
        match="Pipeline module sigma.pipelines.splunk does not have the factory foo_factory",
    ):
        sigmascope.load_backend(
            ("sigma.backends.splunk", "SplunkBackend"),
            ("sigma.pipelines.splunk", "foo_factory"),
        )


def test_invalid_backend_module_throws_exception():
    with pytest.raises(
        ValueError,
        match="Backend module sigma.backends.foo_backend could not be imported",
    ):
        sigmascope.load_backend(
            ("sigma.backends.foo_backend", "SplunkBackend"),
            ("sigma.pipelines.splunk", "splunk_windows_pipeline"),
        )


def test_invalid_backend_class_throws_exception():
    with pytest.raises(
        ValueError,
        match="Backend module sigma.backends.splunk does not have the class FooBackend",
    ):
        sigmascope.load_backend(
            ("sigma.backends.splunk", "FooBackend"),
            ("sigma.pipelines.splunk", "splunk_windows_pipeline"),
        )


def test_invalid_pipeline_path_throws_native_exception():
    with pytest.raises(
        FileNotFoundError,
        match=r"\[Errno 2\] No such file or directory: 'tests/data/foo_pipeline.yaml'",
    ):
        sigmascope.load_backend(
            ("sigma.backends.splunk", "SplunkBackend"), "tests/data/foo_pipeline.yaml"
        )


def test_invalid_non_yaml_path_throws_exception():
    with pytest.raises(
        ValueError,
        match="Failed to load a module or file based on the pipeline spec: tests/data/mixed.csv",
    ):
        sigmascope.load_backend(
            ("sigma.backends.splunk", "SplunkBackend"), "tests/data/mixed.csv"
        )


def test_invalid_yaml_pipeline_throws_native_exception():
    with pytest.raises(yaml.scanner.ScannerError) as e:
        sigmascope.load_backend(
            ("sigma.backends.splunk", "SplunkBackend"),
            "tests/pipeline/invalid_pipeline.yaml",
        )
    assert e.value.problem == "mapping values are not allowed here"
