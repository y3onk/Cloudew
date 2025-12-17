import json
from datetime import datetime, timedelta
from pathlib import Path


# MCP Tool: 법률/규정 준수 여부 체크


class ComplianceTool:
    def __init__(
        self, regulations_path="data/regulations", templates_path="data/templates"
    ):
        self.regulations_path = Path(regulations_path)
        self.templates_path = Path(templates_path)
        self.regulations = self._load_regulations()
        self.templates = self._load_templates()

    # 모든 법령 JSON 파일 로드
    def _load_regulations(self) -> dict:
        regulations = {}

        # 한국 법령
        korea_path = self.regulations_path / "korea"
        if korea_path.exists():
            for json_file in korea_path.glob("*.json"):
                with open(json_file, "r", encoding="utf-8") as f:
                    regulations[json_file.stem] = json.load(f)

        # 국제 법령
        intl_path = self.regulations_path / "international"
        if intl_path.exists():
            for json_file in intl_path.glob("*.json"):
                with open(json_file, "r", encoding="utf-8") as f:
                    regulations[json_file.stem] = json.load(f)

        return regulations

    # 템플릿 로드
    def _load_templates(self) -> dict:
        templates = {}

        if self.templates_path.exists():
            for template_file in self.templates_path.glob("*.md"):
                with open(template_file, "r", encoding="utf-8") as f:
                    templates[template_file.stem] = f.read()

        return templates

    # [Tool 1] 신고 필요 여부 판단
    def check_regulatory_requirements(
        self, finding_data: dict, affected_resources: dict, claude_client=None
    ) -> dict:
        result = {
            "requires_subject_notification": False,  # 정보주체 통지 의무 (1명 이상)
            "requires_kisa_report": False,  # 신고 의무 (1000명 이상 or 해킹 or 민감정보)
            "requires_gdpr_notification": False,
            "reporting_deadline": None,
            "legal_basis": {},
            "reasoning": "",
            "severity_assessment": "LOW",
            "recommended_actions": [],
        }

        # 1. 공통 변수 추출
        severity = finding_data.get("severity", 0)
        finding_type = finding_data.get("type", "")
        estimated_users = affected_resources.get("estimated_users", 0)
        is_hacking = self._is_external_attack(finding_type)
        has_sensitive = self._has_sensitive_data(affected_resources)
        resource_tags = affected_resources.get("tags", {})
        is_eu_data = (
            resource_tags.get("DataResidence") == "EU"
            or resource_tags.get("GDPR_Subject") == "True"
        )

        # 2. 정보통신망법 체크 (침해사고 대응 - 24시간)
        if self._is_incident(finding_type):
            result["requires_kisa_report"] = True
            result["reporting_deadline"] = self._calculate_deadline(24)
            result["legal_basis"]["telecom_law"] = {
                "law": "정보통신망법 제48조의3",
                "reason": "기술적 수단에 의한 침해사고 발생 (24시간 내 신고)",
                "deadline_hours": 24,
            }
            result["recommended_actions"].append("즉시 KISA에 침해사고 신고서 제출")

        # 3. 개인정보보호법 체크 (유출 대응 - 72시간)
        # 1명 이상
        if estimated_users > 0:
            result["requires_subject_notification"] = True
            result["recommended_actions"].append(
                "정보주체에게 유출 사질 통지 (72시간 내)"
            )

            # 1000명 이상 or 민감정보 or 해킹
            if estimated_users >= 1000 or has_sensitive or is_hacking:
                result["requires_kisa_report"] = True

                # 망법(24시간) 기준이 없을 때만 72시간 설정
                if not result["reporting_deadline"]:
                    result["reporting_deadline"] = self._calculate_deadline(72)

                basis_reasons = []
                if estimated_users >= 1000:
                    basis_reasons.append(f"{estimated_users}명 대규모 유출")
                if has_sensitive:
                    basis_reasons.append("민감/고유식별정보 포함")
                if is_hacking:
                    basis_reasons.append("외부 불법 접근에 의한 유출")

                result["legal_basis"]["pipa"] = {
                    "law": "개인정보보호법 제34조",
                    "reason": f"신고 대상 유출 발생 ({', '.join(basis_reasons)})",
                    "deadline_hours": 72,
                }
                result["recommended_actions"].append(
                    "KISA/개인정보보호위원회에 유출 신고"
                )

        # 4. GDPR 체크
        if self._is_eu_applicable(finding_data) or is_eu_data:
            result["requires_gdpr_notification"] = True
            result["legal_basis"]["gdpr"] = {
                "law": "GDPR Article 33",
                "reason": "EU 거주자 데이터 관련 또는 EU 지역 공격 탐지",
                "deadline_hours": 72,
            }
            result["recommended_actions"].append("해당 EU 국가 DPA 통보 검토")

        # 5. 심각도 평가
        if result["requires_kisa_report"] or result["requires_gdpr_notification"]:
            if severity >= 7.0 or estimated_users >= 1000 or is_hacking:
                result["severity_assessment"] = "HIGH"
            else:
                result["severity_assessment"] = "MEDIUM"

        # 6. 판단 근거 생성
        result["reasoning"] = self._generate_reasoning(result)

        # 7. Claude 추가 분석 (선택)
        if claude_client and result["severity_assessment"] in ["HIGH", "MEDIUM"]:
            try:
                claude_analysis = self._get_claude_analysis(
                    claude_client, finding_data, affected_resources, result
                )
                result["claude_analysis"] = claude_analysis
            except Exception as e:
                result["claude_analysis"] = f"Claude 분석 실패: {str(e)}"

        return result

    # [Tool 2] 보고서 생성
    def generate_incident_report(
        self,
        finding_data: dict,
        compliance_check: dict,
        company_info: dict,
        claude_client=None,
    ) -> dict:
        if not compliance_check.get("requires_kisa_report"):
            return {"kisa_report_markdown": None, "message": "KISA 신고 대상 아님"}

        # 템플릿 로드
        template = self.templates.get("kisa_report", "")

        # 변수 채우기
        variables = self._prepare_template_variables(
            finding_data, compliance_check, company_info
        )

        # 템플릿 렌더링
        report = self._render_template(template, variables)

        return {
            "kisa_report_markdown": report,
            "report_id": f"INC-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "required_attachments": [
                "GuardDuty Finding JSON",
                "CloudTrail 로그",
                "영향 범위 분석 (작성 중)",
            ],
        }

    # 헬퍼 메서드들
    # 침해사고 여부 판단
    def _is_incident(self, finding_type: str) -> bool:
        incident_keywords = [
            "UnauthorizedAccess",
            "Trojan",
            "Backdoor",
            "CryptoCurrency",
            "Exfiltration",
            "Impact",
            "Recon",
        ]
        return any(keyword in finding_type for keyword in incident_keywords)

    # 외부 공격 여부
    def _is_external_attack(self, finding_type: str) -> bool:
        return any(
            keyword in finding_type
            for keyword in ["UnauthorizedAccess", "MaliciousIP", "Trojan", "Backdoor"]
        )

    # 민감정보 포함 여부 추론
    def _has_sensitive_data(self, affected_resources: dict) -> bool:
        sensitive_keywords = [
            "card",
            "credit",
            "payment",
            "ssn",
            "passport",
            "driver",
            "medical",
            "health",
            "biometric",
        ]

        all_resources = (
            affected_resources.get("s3_buckets", [])
            + affected_resources.get("rds_instances", [])
            + affected_resources.get("dynamodb_tables", [])
        )

        for resource in all_resources:
            if any(kw in str(resource).lower() for kw in sensitive_keywords):
                return True

        return False

    # GDPR 적용 여부 판단
    def _is_eu_applicable(self, finding_data: dict) -> bool:
        try:
            remote_ip_details = (
                finding_data.get("service", {})
                .get("action", {})
                .get("awsApiCallAction", {})
                .get("remoteIpDetails", {})
            )
            country = remote_ip_details.get("country", {}).get("countryName", "")

            eu_countries = [
                "Austria",
                "Belgium",
                "Bulgaria",
                "Croatia",
                "Cyprus",
                "Czech Republic",
                "Denmark",
                "Estonia",
                "Finland",
                "France",
                "Germany",
                "Greece",
                "Hungary",
                "Ireland",
                "Italy",
                "Latvia",
                "Lithuania",
                "Luxembourg",
                "Malta",
                "Netherlands",
                "Poland",
                "Portugal",
                "Romania",
                "Slovakia",
                "Slovenia",
                "Spain",
                "Sweden",
                "Iceland",
                "Liechtenstein",
                "Norway",
            ]

            return country in eu_countries
        except:
            return False

    # 신고 기한 계산
    def _calculate_deadline(self, hours: int) -> str:
        deadline = datetime.utcnow() + timedelta(hours=hours)
        return deadline.isoformat() + "Z"

    # 판단 근거 생성
    def _generate_reasoning(self, result: dict) -> str:
        reasons = []

        for key, basis in result.get("legal_basis", {}).items():
            reasons.append(f"{basis['law']}: {basis['reason']}")

        if not reasons:
            return "추가 검토 필요"

        return " | ".join(reasons)

    def _get_claude_analysis(
        self, claude_client, finding_data, affected_resources, result
    ):
        # Claude에게 추가 분석 요청
        prompt = f"""
GuardDuty Finding 분석 및 규정 준수 판단 검토:

Finding 정보:
- Type: {finding_data.get('type')}
- Severity: {finding_data.get('severity')}
- Description: {finding_data.get('description', '')}

영향 리소스:
{json.dumps(affected_resources, indent=2, ensure_ascii=False)}

현재 판단:
{json.dumps(result, indent=2, ensure_ascii=False)}

이 판단이 적절한지 검토하고, 간결한 추가 의견을 제시해주세요.
"""

        # Claude API 호출
        response = claude_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}],
        )

        return response.content[0].text

    # 템플릿 변수 준비
    def _prepare_template_variables(self, finding_data, compliance_check, company_info):
        # 공격자 정보
        attacker_ip = self._extract_attacker_ip(finding_data)
        affected_resources = self._extract_affected_resources(finding_data)

        # 즉시 조치사항
        immediate_actions = [
            "✅ 침해 계정 Access Key 즉시 비활성화 완료",
            f"✅ 공격 발신 IP ({attacker_ip}) 차단 완료",
            "✅ 영향 범위 조사 착수",
            "✅ 증거 자료 확보 (CloudTrail 로그 백업)",
        ]

        ongoing_actions = [
            "상세 포렌식 분석 진행 중",
            "영향받은 데이터 범위 특정 작업 중",
            "추가 보안 취약점 점검 중",
        ]

        return {
            "company_name": company_info.get("company_name", "[기관명]"),
            "leaked_data_types": "조사 중 (추정: 이메일, 연락처, 사용자 ID 등)",
            "estimated_users": compliance_check.get("estimated_users", "조사 중"),
            "finding_type": finding_data.get("type", "Unknown"),
            "detected_at": finding_data.get("service", {}).get(
                "eventFirstSeen", datetime.utcnow().isoformat()
            ),
            "attacker_ip": attacker_ip,
            "affected_resources": affected_resources,
            "incident_start_time": finding_data.get("service", {}).get(
                "eventFirstSeen", "조사 중"
            ),
            "detection_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "incident_description": finding_data.get(
                "description", "외부로부터 비정상적인 접근 시도 탐지"
            ),
            "severity": finding_data.get("severity", "Unknown"),
            "immediate_actions": "\n".join(
                f"- {action}" for action in immediate_actions
            ),
            "ongoing_actions": "\n".join(f"- {action}" for action in ongoing_actions),
            "dpo_name": company_info.get("dpo_name", "[책임자명]"),
            "dpo_email": company_info.get("dpo_email", "security@company.com"),
            "dpo_phone": company_info.get("dpo_phone", "[연락처]"),
            "dpo_contact": company_info.get("dpo_phone", "[연락처]"),
            "reporter_name": company_info.get("reporter_name", "[담당자명]"),
            "reporter_dept": company_info.get("reporter_dept", "[부서명]"),
            "reporter_position": company_info.get("reporter_position", "[직위]"),
            "reporter_contact": company_info.get("reporter_contact", "[연락처]"),
            "report_datetime": datetime.utcnow().strftime(
                "%Y년 %m월 %d일 %H시 %M분 (UTC)"
            ),
        }

    # 공격자 IP 추출
    def _extract_attacker_ip(self, finding_data) -> str:
        try:
            remote_ip_details = (
                finding_data.get("service", {})
                .get("action", {})
                .get("awsApiCallAction", {})
                .get("remoteIpDetails", {})
            )
            ip = remote_ip_details.get("ipAddressV4", "Unknown")
            country = remote_ip_details.get("country", {}).get("countryName", "Unknown")
            city = remote_ip_details.get("city", {}).get("cityName", "Unknown")
            return f"{ip} ({city}, {country})"
        except:
            return "조사 중"

    # 영향받은 리소스 추출
    def _extract_affected_resources(self, finding_data) -> str:
        try:
            resource = finding_data.get("resource", {})
            resource_type = resource.get("resourceType", "Unknown")

            if resource_type == "AccessKey":
                user_name = resource.get("accessKeyDetails", {}).get(
                    "userName", "Unknown"
                )
                return f"IAM User: {user_name}"
            elif resource_type == "Instance":
                instance_id = resource.get("instanceDetails", {}).get(
                    "instanceId", "Unknown"
                )
                return f"EC2 Instance: {instance_id}"
            else:
                return resource_type
        except:
            return "조사 중"

    # 템플릿 렌더링 (간단한 변수 치환)
    def _render_template(self, template: str, variables: dict) -> str:
        result = template
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", str(value))
        return result
