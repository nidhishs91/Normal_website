name: DevOps Normal Change

on:
  push:
    branches:
      - main
  workflow_dispatch:

permissions:
  contents: read
  security-events: read

jobs:
  ServiceNowDevOpsChange:
    runs-on: ubuntu-latest
    name: ServiceNow DevOps Change (Prod Deploy)

    steps:
      # -----------------------------------
      # CHECKOUT
      # -----------------------------------
      - name: Checkout
        uses: actions/checkout@v4

      # -----------------------------------
      # PARSE JUNIT XML
      # -----------------------------------
      - name: Parse JUnit XML and count tests
        id: parse_xml
        shell: bash
        run: |
          python3 <<'PY'
          import os
          import xml.etree.ElementTree as ET

          xml_file = "testResultsFolder/valid-unit.xml"
          total = passed = failed = skipped = 0
          duration = 0.0

          try:
              root = ET.parse(xml_file).getroot()
              for tc in root.iter("testcase"):
                  total += 1
                  if tc.find("failure") is not None or tc.find("error") is not None:
                      failed += 1
                  elif tc.find("skipped") is not None:
                      skipped += 1
                  else:
                      passed += 1

              duration = float(root.attrib.get("time", "0.0") or 0.0)
          except Exception as e:
              print(f"JUnit parse error: {e}")

          with open(os.environ["GITHUB_OUTPUT"], "a") as f:
              f.write(
                  f"total={total}\n"
                  f"passed={passed}\n"
                  f"failed={failed}\n"
                  f"skipped={skipped}\n"
                  f"duration={duration}\n"
              )
          PY

      # -----------------------------------
      # SEND TEST RESULTS TO SERVICENOW
      # -----------------------------------
      - name: ServiceNow DevOps Unit Test Results
        if: always()
        uses: ServiceNow/servicenow-devops-test-report@dev
        with:
          devops-integration-user-name: ${{ secrets.SN_DEVOPS_USER_DEMO14 }}
          devops-integration-user-password: ${{ secrets.SN_DEVOPS_PASSWORD_DEMO14 }}
          instance-url: ${{ secrets.SN_INSTANCE_URL_DEMO14 }}
          tool-id: ${{ secrets.SN_ORCHESTRATION_TOOL_ID_DEMO14 }}
          context-github: ${{ toJSON(github) }}
          job-name: ServiceNow DevOps Change (Prod Deploy)
          xml-report-filename: testResultsFolder/valid-unit.xml
          test-summary-name: GitHub Test Summary - JUnit - ${{ github.run_id }}

      # -----------------------------------
      # CREATE SERVICENOW CHANGE
      # -----------------------------------
      - name: Create ServiceNow Normal Change
        id: CreateChange
        if: always()
        uses: ServiceNow/servicenow-devops-change@v6.1.0
        with:
          devops-integration-user-name: ${{ secrets.SN_DEVOPS_USER_DEMO14 }}
          devops-integration-user-password: ${{ secrets.SN_DEVOPS_PASSWORD_DEMO14 }}
          instance-url: ${{ secrets.SN_INSTANCE_URL_DEMO14 }}
          tool-id: ${{ secrets.SN_ORCHESTRATION_TOOL_ID_DEMO14 }}
          context-github: ${{ toJSON(github) }}
          job-name: ServiceNow DevOps Change (Prod Deploy)
          change-request: >
            {
              "attributes": {
                "short_description": "DevOps Normal Change - GitHub",
                "description": "Deployment with automated test & security validation",
                "chg_model": {
                  "name": "DevOps Simplified"
                }
              }
            }
          interval: "15"
          timeout: "900"

      # -----------------------------------
      # GHAS REPORT + SERVICENOW SCAN SUMMARY WRITE
      # -----------------------------------
      - name: Export GHAS report and write scan summary to ServiceNow
        if: always() && steps.CreateChange.outputs['change-request-sys-id'] != ''
        shell: bash
        env:
          GH_TOKEN: ${{ secrets.GHAS_PAT }}

          SN_URL: ${{ secrets.SN_INSTANCE_URL_DEMO14 }}
          SN_USER: ${{ secrets.SN_DEVOPS_USER_DEMO14 }}
          SN_PASS: ${{ secrets.SN_DEVOPS_PASSWORD_DEMO14 }}

          CHANGE_SYS_ID: ${{ steps.CreateChange.outputs['change-request-sys-id'] }}

          # Optional: if you know the Application Release sys_id, put it in this secret
          APP_RELEASE_SYS_ID: ${{ secrets.SN_APP_RELEASE_SYS_ID }}

          # Optional: keep defaults unless you want to override
          SN_SUMMARY_TABLE: sn_vul_app_vul_scan_summary
          GHAS_SOURCE_LABEL: GitHub Advanced Security
          SOURCE_SDLC_STATUS: GitHub Actions
          GHAS_POLICY: GitHub Advanced Security

          REPO: ${{ github.repository }}
          RUN_ID: ${{ github.run_id }}
          RUN_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
        run: |
          python3 ghas_servicenow.py
