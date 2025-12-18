import boto3
import time
import uuid
from typing import List, Dict, Optional
from decimal import Decimal


class ChatStorage:
    def __init__(self):
        self.dynamodb = boto3.resource("dynamodb", region_name="ap-northeast-2")
        self.table = self.dynamodb.Table("chat-history")

    # 메시지를 DynamoDB에 저장
    def save_message(
        self,
        session_id: str,
        role: str,
        content: str,
        user_name: str,
        incident_id: Optional[str] = None,
        mcp_tools_used: Optional[List[str]] = None,
        report_type: Optional[str] = None,
    ) -> Dict:
        """
        Args:
            session_id: 세션 ID
            role: "user" | "assistant" | "system"
            content: 메시지 내용
            user_name: 사용자 이름
            incident_id: 관련 사건 ID (선택)
            mcp_tools_used: 사용된 MCP 도구 목록 (선택)
            report_type: 보고서 타입 (선택)

        Returns:
            저장된 Item
        """
        now = int(time.time())

        item = {
            "session_id": session_id,
            "timestamp": now,
            "message_id": str(uuid.uuid4()),
            "role": role,
            "content": content,
            "user_name": user_name,
            "ttl": now + (90 * 24 * 3600),  # 3개월
        }

        # 선택 필드 추가
        if incident_id:
            item["incident_id"] = incident_id

        if mcp_tools_used:
            item["mcp_tools_used"] = mcp_tools_used

        if report_type:
            item["report_type"] = report_type

        self.table.put_item(Item=item)
        return item

    # 세션의 모든 메시지 조회 (시간순 정렬)
    def get_session_messages(self, session_id: str) -> List[Dict]:
        """
        Args:
            session_id: 세션 ID

        Returns:
            메시지 리스트 (오래된 순)
        """
        response = self.table.query(
            KeyConditionExpression="session_id = :sid",
            ExpressionAttributeValues={":sid": session_id},
            ScanIndexForward=True,  # 오래된 순
        )

        return response.get("Items", [])

    # 사용자의 최근 세션 목록 조회
    def get_user_sessions(self, user_name: str, limit: int = 20) -> List[Dict]:
        """
        Args:
            user_name: 사용자 이름
            limit: 조회 개수 (기본 20)

        Returns:
            세션 리스트 (최신순)
        """
        response = self.table.query(
            IndexName="user-sessions-index",
            KeyConditionExpression="user_name = :user",
            ExpressionAttributeValues={":user": user_name},
            ScanIndexForward=False,  # 최신순
            Limit=limit,
        )

        return response.get("Items", [])

    # 세션 존재 여부 확인
    def session_exists(self, session_id: str) -> bool:
        """
        Args:
            session_id: 세션 ID

        Returns:
            존재하면 True
        """
        response = self.table.query(
            KeyConditionExpression="session_id = :sid",
            ExpressionAttributeValues={":sid": session_id},
            Limit=1,
        )

        return len(response.get("Items", [])) > 0
