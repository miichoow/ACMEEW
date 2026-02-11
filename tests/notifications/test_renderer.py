"""Tests for acmeeh.notifications.renderer.TemplateRenderer."""

from __future__ import annotations

from enum import StrEnum
from unittest.mock import patch

import pytest

from acmeeh.notifications.renderer import TemplateRenderer

# ---------------------------------------------------------------------------
# Helpers — use a minimal NotificationType-like enum for tests
# ---------------------------------------------------------------------------


class _FakeNotificationType(StrEnum):
    """Fake notification type for testing without importing the real one."""

    TEST_EVENT = "test_event"
    EXPIRATION_WARNING = "expiration_warning"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTemplateRendererInit:
    """Tests for TemplateRenderer initialization."""

    @patch("acmeeh.notifications.renderer.PackageLoader")
    @patch("acmeeh.notifications.renderer.ChoiceLoader")
    @patch("acmeeh.notifications.renderer.Environment")
    def test_init_without_custom_templates(
        self,
        mock_env_cls,
        mock_choice_loader,
        mock_pkg_loader,
    ):
        """Without templates_path, only PackageLoader is used."""
        renderer = TemplateRenderer(templates_path=None)

        mock_choice_loader.assert_called_once()
        loaders = mock_choice_loader.call_args[0][0]
        assert len(loaders) == 1  # Only PackageLoader
        mock_pkg_loader.assert_called_once_with(
            "acmeeh.notifications",
            "templates",
        )

    @patch("acmeeh.notifications.renderer.FileSystemLoader")
    @patch("acmeeh.notifications.renderer.PackageLoader")
    @patch("acmeeh.notifications.renderer.ChoiceLoader")
    @patch("acmeeh.notifications.renderer.Environment")
    def test_init_with_custom_templates(
        self,
        mock_env_cls,
        mock_choice_loader,
        mock_pkg_loader,
        mock_fs_loader,
    ):
        """With templates_path, FileSystemLoader is prepended."""
        renderer = TemplateRenderer(templates_path="/custom/templates")

        mock_fs_loader.assert_called_once_with("/custom/templates")
        mock_choice_loader.assert_called_once()
        loaders = mock_choice_loader.call_args[0][0]
        assert len(loaders) == 2  # FileSystemLoader + PackageLoader


class TestTemplateRendererRender:
    """Tests for TemplateRenderer.render."""

    def test_render_with_temp_templates(self, tmp_path):
        """Render uses actual templates from a temporary directory."""
        # Create template files
        subject_file = tmp_path / "test_event_subject.txt"
        subject_file.write_text("Alert: {{ domain }}", encoding="utf-8")

        body_file = tmp_path / "test_event_body.html"
        body_file.write_text(
            "<p>Certificate for {{ domain }} expires on {{ date }}.</p>",
            encoding="utf-8",
        )

        renderer = TemplateRenderer(templates_path=str(tmp_path))
        subject, body = renderer.render(
            _FakeNotificationType.TEST_EVENT,
            {"domain": "example.com", "date": "2026-03-01"},
        )

        assert subject == "Alert: example.com"
        assert "example.com" in body
        assert "2026-03-01" in body

    def test_render_strips_subject(self, tmp_path):
        """Subject is stripped of leading/trailing whitespace."""
        subject_file = tmp_path / "test_event_subject.txt"
        subject_file.write_text("  Hello {{ name }}  \n", encoding="utf-8")

        body_file = tmp_path / "test_event_body.html"
        body_file.write_text("<p>Body</p>", encoding="utf-8")

        renderer = TemplateRenderer(templates_path=str(tmp_path))
        subject, _ = renderer.render(
            _FakeNotificationType.TEST_EVENT,
            {"name": "World"},
        )

        assert subject == "Hello World"

    def test_render_uses_notification_type_value(self, tmp_path):
        """Template filenames are derived from notification_type.value."""
        subject_file = tmp_path / "expiration_warning_subject.txt"
        subject_file.write_text("Expiration: {{ domain }}", encoding="utf-8")

        body_file = tmp_path / "expiration_warning_body.html"
        body_file.write_text("<p>Expires soon</p>", encoding="utf-8")

        renderer = TemplateRenderer(templates_path=str(tmp_path))
        subject, body = renderer.render(
            _FakeNotificationType.EXPIRATION_WARNING,
            {"domain": "test.example.com"},
        )

        assert "test.example.com" in subject
        assert "Expires soon" in body

    def test_render_missing_template_raises(self, tmp_path):
        """Missing template file raises TemplateNotFound."""
        from jinja2.exceptions import TemplateNotFound

        renderer = TemplateRenderer(templates_path=str(tmp_path))
        with pytest.raises(TemplateNotFound):
            renderer.render(
                _FakeNotificationType.TEST_EVENT,
                {"domain": "example.com"},
            )

    def test_render_autoescape(self, tmp_path):
        """Autoescaping is enabled — HTML in context values is escaped."""
        subject_file = tmp_path / "test_event_subject.txt"
        subject_file.write_text("{{ title }}", encoding="utf-8")

        body_file = tmp_path / "test_event_body.html"
        body_file.write_text("<p>{{ content }}</p>", encoding="utf-8")

        renderer = TemplateRenderer(templates_path=str(tmp_path))
        subject, body = renderer.render(
            _FakeNotificationType.TEST_EVENT,
            {"title": "Safe Title", "content": "<script>alert('xss')</script>"},
        )

        # Body should have escaped HTML
        assert "&lt;script&gt;" in body
        assert "<script>" not in body

    def test_render_returns_tuple(self, tmp_path):
        """render returns a (subject, body) tuple."""
        subject_file = tmp_path / "test_event_subject.txt"
        subject_file.write_text("Subject", encoding="utf-8")

        body_file = tmp_path / "test_event_body.html"
        body_file.write_text("Body", encoding="utf-8")

        renderer = TemplateRenderer(templates_path=str(tmp_path))
        result = renderer.render(_FakeNotificationType.TEST_EVENT, {})

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result[0] == "Subject"
        assert result[1] == "Body"
