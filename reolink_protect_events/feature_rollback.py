"""Durable, resumable feature rollback across UI files and PostgreSQL."""
from .features import FeatureError


def recover_legacy_state(state, ui_manifest):
    """Old helpers could restore UI then fail before recording a rollback phase."""
    if not state.get("rollbackPhase") and ui_manifest.get("state") == "rolled_back":
        return dict(state, rollbackPhase="ui", state="rolling_back", recoveredLegacyRollback=True)
    return state


def resume_rollback(state, persist, patch, cameras, preflight):
    """Every phase repeats ownership/CAS checks; no cross-resource transaction."""
    phase = state.get("rollbackPhase")
    if phase not in (None, "ui", "cameras", "complete"):
        raise FeatureError("Unknown feature rollback phase")
    if phase is None:
        preflight()  # Controls dependency and user changes checked before writes.
        state["rollbackPhase"] = "ui"
        state["state"] = "rolling_back"
        persist(state)
    # Repeat even when persisted phase is later: a new UI layer installed since
    # the last attempt must stop the camera rollback, never be silently bypassed.
    patch.rollback(state["uiManifest"])
    state["rollbackPhase"] = "cameras"
    persist(state)
    cameras.rollback(state["cameraManifest"])
    state["rollbackPhase"] = "complete"
    state["state"] = "rolled_back"
    state["restartRequired"] = True
    persist(state)
    return state
