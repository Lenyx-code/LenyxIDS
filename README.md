
```
cyber_forensic_pme
├─ .dockerignore
├─ app
│  ├─ api
│  │  ├─ routes
│  │  │  ├─ alertes.py
│  │  │  ├─ include.py
│  │  │  ├─ monitoring.py
│  │  │  ├─ packet.py
│  │  │  ├─ reports.py
│  │  │  └─ yara.py
│  │  └─ utils
│  │     ├─ broadcast.py
│  │     ├─ database.py
│  │     ├─ loop_holder.py
│  │     ├─ router.py
│  │     └─ subscribers.py
│  ├─ core
│  │  ├─ analyser.py
│  │  ├─ forencic.py
│  │  ├─ monitoring
│  │  │  ├─ agent.py
│  │  │  └─ file_watcher.py
│  │  ├─ settings.py
│  │  ├─ sniffer.py
│  │  └─ yara_engine.py
│  ├─ database
│  │  ├─ mongodb
│  │  │  ├─ connection.py
│  │  │  ├─ Dockerfile
│  │  │  ├─ models
│  │  │  │  ├─ alert.py
│  │  │  │  ├─ alert_monitor.py
│  │  │  │  ├─ forensic_report.py
│  │  │  │  └─ packet.py
│  │  │  └─ repository.py
│  │  └─ mysql
│  │     └─ Dockerfile
│  ├─ Dockerfile
│  ├─ main.py
│  ├─ requirements.txt
│  ├─ setup_routing.sh
│  ├─ storage
│  │  ├─ captures
│  │  │  ├─ evidence-brute-force.txt
│  │  │  ├─ evidence-fingerprint.txt
│  │  │  ├─ evidence-ping-flood.txt
│  │  │  ├─ evidence-port-scan.txt
│  │  │  ├─ evidence-sql_injection.txt
│  │  │  └─ evidence-syn-flood.txt
│  │  ├─ pcap
│  │  ├─ reports
│  │  └─ yara
│  │     ├─ builtin
│  │     │  ├─ malware_generic.yar
│  │     │  ├─ ransomware.yar
│  │     │  ├─ suspicious_scripts.yar
│  │     │  └─ webshells.yar
│  │     ├─ compiled.yarc
│  │     ├─ rules
│  │     └─ uploads
│  ├─ tests
│  │  └─ storage
│  │     └─ captures
│  │        ├─ evidence-fingerprint.txt
│  │        └─ evidence-port-scan.txt
│  └─ utils
│     └─ datetime_utils.py
├─ docker-cmd.md
├─ docker-compose.yml
├─ dockercom.prod.txt
├─ tests
│  ├─ agent.py
│  ├─ agent.spec
│  ├─ brute_force_file
│  │  ├─ pwd.txt
│  │  └─ username.txt
│  ├─ cmd-test.txt
│  ├─ Dockerfile
│  ├─ entrypoint.sh
│  ├─ run_attacks.py
│  └─ storage
│     ├─ captures
│     └─ rapport
└─ web
   ├─ Dockerfile
   ├─ eslint.config.js
   ├─ index.html
   ├─ package-lock.json
   ├─ package.json
   ├─ postcss.config.js
   ├─ public
   │  ├─ favicon.svg
   │  └─ icons.svg
   ├─ README.md
   ├─ src
   │  ├─ App.css
   │  ├─ App.jsx
   │  ├─ assets
   │  │  ├─ hero.png
   │  │  ├─ react.svg
   │  │  └─ vite.svg
   │  ├─ components
   │  │  ├─ charts
   │  │  ├─ layout
   │  │  │  ├─ Layout.jsx
   │  │  │  └─ Sidebar.jsx
   │  │  └─ ui
   │  │     ├─ AlertMonitorToast.jsx
   │  │     ├─ AlertToast.jsx
   │  │     ├─ Badge.jsx
   │  │     └─ LiveIndicator.jsx
   │  ├─ css
   │  ├─ hooks
   │  │  └─ useSSE.jsx
   │  ├─ index.css
   │  ├─ js
   │  ├─ main.jsx
   │  ├─ services
   │  │  └─ api.jsx
   │  ├─ store
   │  │  └─ sseStore.jsx
   │  ├─ utils
   │  │  ├─ formatters.js
   │  │  └─ toastUtils.js
   │  └─ views
   │     ├─ Alerts.jsx
   │     ├─ Analyse.jsx
   │     ├─ Dashboard.jsx
   │     ├─ FileAlertStab.jsx
   │     ├─ Monitoring.jsx
   │     ├─ MonitoringAlerts.jsx
   │     ├─ Reports.jsx
   │     └─ Settings.jsx
   ├─ tailwind.config.js
   └─ vite.config.js

```