import pytest

import sigmascope


def test_load_valid_backend():
    sigmascope.load_backend(
        ('sigma.backends.splunk', 'SplunkBackend'),
        ('sigma.pipelines.splunk', 'splunk_windows_pipeline')
    )


def test_invalid_pipeline_module_throws_exception():
    with pytest.raises(ValueError, match='Pipeline module sigma.pipelines.foo_pipeline could not be imported'):
        sigmascope.load_backend(
            ('sigma.backends.splunk', 'SplunkBackend'),
            ('sigma.pipelines.foo_pipeline', 'splunk_windows_pipeline')
        )


def test_invalid_pipeline_factory_throws_exception():
    with pytest.raises(ValueError, match='Pipeline module sigma.pipelines.splunk does not have the factory foo_factory'):
        sigmascope.load_backend(
            ('sigma.backends.splunk', 'SplunkBackend'),
            ('sigma.pipelines.splunk', 'foo_factory')
        )
