"""
Automated test & WebSocket load test suite for LAN Chat App.
Run: pytest test_lan_chat.py -v   (or: python3 test_lan_chat.py)
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import lan_chat_app


class LanChatTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        tmp_path = Path(self.tmp_dir.name)
        lan_chat_app.DB_PATH = tmp_path / "test_lan_chat.db"
        lan_chat_app.UPLOAD_DIR = tmp_path / "uploads"
        lan_chat_app.UPLOAD_DIR.mkdir(exist_ok=True)
        lan_chat_app.manager.active.clear()
        lan_chat_app.manager.huddles.clear()
        lan_chat_app.LOCALHOST_IPS.add("testclient")
        lan_chat_app.init_db()
        self.client = TestClient(lan_chat_app.app)

    def tearDown(self) -> None:
        self.client.close()
        self.tmp_dir.cleanup()

    def _auth(self, username: str, pin: str = "1234") -> dict[str, str]:
        res = self.client.post("/api/auth", json={"username": username, "pin": pin})
        self.assertEqual(res.status_code, 200, res.text)
        return res.json()

    def test_auth_admin_and_profile(self) -> None:
        u1 = self._auth("Anuj", "1234")
        u2 = self._auth("Ambuj", "5678")
        self.assertEqual(u1["role"], "admin")
        self.assertEqual(u2["role"], "member")

        # Update department & status
        prof = self.client.post(
            "/api/me/profile",
            headers={"X-Auth-Token": u1["token"]},
            json={"department": "Engineering", "status_text": "Building LAN Chat"},
        )
        self.assertEqual(prof.status_code, 200)

        # Admin overview & white-label config
        ov = self.client.get("/api/admin/overview", headers={"X-Auth-Token": u1["token"]})
        self.assertEqual(ov.status_code, 200)
        self.assertEqual(ov.json()["stats"]["total_users"], 2)

        cfg = self.client.get("/api/config")
        self.assertEqual(cfg.status_code, 200)
        self.assertIn("brand_name", cfg.json())

    def test_passcode_group_and_announce_only(self) -> None:
        admin = self._auth("AdminUser", "1111")
        member = self._auth("MemberUser", "2222")

        # Create passcode-protected + announcement-only group
        grp = self.client.post(
            "/api/rooms",
            headers={"X-Auth-Token": admin["token"]},
            json={"name": "SecretOps", "passcode": "9999", "announce_only": True, "disappear_seconds": 60},
        )
        self.assertEqual(grp.status_code, 200, grp.text)
        room = grp.json()["room"]
        self.assertTrue(room["has_passcode"])
        self.assertTrue(room["announce_only"])

        # Wrong passcode fails
        bad_join = self.client.post(
            f"/api/rooms/{room['id']}/join",
            headers={"X-Auth-Token": member["token"]},
            json={"passcode": "0000"},
        )
        self.assertEqual(bad_join.status_code, 403)

        # Correct passcode succeeds
        ok_join = self.client.post(
            f"/api/rooms/{room['id']}/join",
            headers={"X-Auth-Token": member["token"]},
            json={"passcode": "9999"},
        )
        self.assertEqual(ok_join.status_code, 200)

        # Announcement-only blocks non-admin member over WebSocket
        with self.client.websocket_connect(f"/ws/MemberUser?token={member['token']}") as ws:
            ws.receive_json()  # presence
            ws.send_json({"type": "message", "room_id": room["id"], "content": "Hello?", "msg_type": "text"})
            err = ws.receive_json()
            self.assertEqual(err["type"], "error")

    def test_webhook_fts5_and_offline_ai(self) -> None:
        u1 = self._auth("Anuj", "1234")
        wh = self.client.post(
            "/api/webhooks/general",
            json={"sender": "GiteaBot", "text": "Build #77 passed on port 8000!"},
        )
        self.assertEqual(wh.status_code, 200, wh.text)

        # FTS5 search
        srch = self.client.get("/api/search?q=Build", headers={"X-Auth-Token": u1["token"]})
        self.assertEqual(srch.status_code, 200)
        self.assertTrue(any("Build #77" in r["content"] for r in srch.json()["results"]))

        # Offline AI /summarize & /ask
        ai_res = self.client.post(
            "/api/ai",
            headers={"X-Auth-Token": u1["token"]},
            json={
                "room_id": "group:general",
                "mode": "ask",
                "query": "port 8000",
                "messages": [{"sender": "GiteaBot", "content": "Build #77 passed on port 8000!"}],
            },
        )
        self.assertEqual(ai_res.status_code, 200)
        self.assertIn("8000", ai_res.json()["answer"])

    def test_websocket_load_burst(self) -> None:
        u1 = self._auth("LoadA", "1234")
        u2 = self._auth("LoadB", "5678")
        with self.client.websocket_connect(f"/ws/LoadA?token={u1['token']}") as ws1:
            ws1.receive_json()  # initial presence
            seen = 0
            for i in range(15):
                ws1.send_json({
                    "type": "message",
                    "room_id": "group:general",
                    "content": f"Burst message #{i}",
                    "msg_type": "text",
                })
                ev = ws1.receive_json()
                if ev.get("type") == "message" and ev["message"]["content"] == f"Burst message #{i}":
                    seen += 1
            self.assertEqual(seen, 15)

        # Verify LoadB can fetch all 15 burst messages from SQLite
        res = self.client.get(
            "/api/rooms/group:general/messages?limit=50",
            headers={"X-Auth-Token": u2["token"]},
        )
        self.assertEqual(res.status_code, 200)
        contents = [m["content"] for m in res.json()["messages"]]
        for i in range(15):
            self.assertIn(f"Burst message #{i}", contents)


if __name__ == "__main__":
    unittest.main(verbosity=2)
