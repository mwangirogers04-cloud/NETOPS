export const NETOPS_FAQS = [
  {
    id: "faq-new-device",
    category: "Device Admission & Security",
    question: "What happens when a new or unknown device connects to the LAN?",
    answer: "When a new device connects, NETOPS detects it instantly via active ARP and DHCP monitoring. Under zero-trust security policy, new and unrecognized devices are automatically quarantined and denied internet access until explicitly approved by an administrator or granted access through an authorized schedule."
  },
  {
    id: "faq-offline-quarantine",
    category: "Device Admission & Security",
    question: "Why does a device show 'Offline' when it is quarantined or isolated?",
    answer: "When a device is quarantined or isolated by the firewall, its WAN and internet access are blocked. NETOPS reflects this security state by marking its connection as 'Offline'. It will only switch to 'Online' once the device is granted active, authorized internet access."
  },
  {
    id: "faq-reject-delete",
    category: "Device Admission & Security",
    question: "What happens if a device is rejected or deleted from the system?",
    answer: "Rejecting a device immediately revokes its internet access and places it into quarantine. If an existing device is deleted, its access authorization is revoked immediately, denying it internet access until it goes through the onboarding approval procedure again."
  },
  {
    id: "faq-schedule-quarantine",
    category: "Access Schedules & Time Controls",
    question: "If a quarantined device is scheduled, does it exit quarantine immediately?",
    answer: "No. When a quarantined device is scheduled (for example, from 18:10 to 18:30), it remains quarantined and offline until the exact scheduled start time arrives (18:10). At 18:10, it automatically exits quarantine and receives internet access. At 18:30, it automatically re-quarantines itself until the next scheduled cycle."
  },
  {
    id: "faq-rejected-scheduled",
    category: "Access Schedules & Time Controls",
    question: "What if a newly detected device is rejected but also scheduled for later?",
    answer: "A rejected device remains quarantined and blocked from internet access until its scheduled time arrives. When the scheduled window opens, it still requires administrator or developer authorization before gaining internet access because it is an unapproved new device."
  },
  {
    id: "faq-auto-refresh",
    category: "System Performance & Monitoring",
    question: "Do I need to keep manually refreshing the dashboard to see updates?",
    answer: "No. NETOPS Version 2 features continuous background synchronization that polls and refreshes connected devices, quarantine states, access schedules, patch tasks, and firewall status every 3 seconds automatically without reloading the page."
  },
  {
    id: "faq-patch-updates",
    category: "Endpoint Patching & Health",
    question: "Why was a device showing 'updates needed' with 0 updates or stuck at 70%?",
    answer: "NETOPS includes an automatic patch reconciliation service. Endpoints with 0 pending updates are normalized to 'Up to date' status, and jobs lingering at intermediate stages (such as 70%) are verified against local package managers (APT/Windows Update) and automatically reconciled."
  },
  {
    id: "faq-supported-firewalls",
    category: "Firewalls & Infrastructure",
    question: "Which firewall appliances and hardware platforms are supported?",
    answer: "NETOPS provides native drivers and dynamic API integrations for Sophos XG/XGS, Fortinet FortiGate, MikroTik RouterOS, pfSense / OPNsense, Cisco ASA, Linux iptables/nftables, Palo Alto PAN-OS, and Check Point Gaia."
  },
  {
    id: "faq-services-offered",
    category: "Services & Technical Support",
    question: "What professional IT and infrastructure services do you offer?",
    answer: "We offer 5 professional services:\n• 📹 CCTV Installation (Commercial & residential IP/analog surveillance setups)\n• 🔌 Structured Cabling (Cat6/Fiber optic trunking, rack dressing & patch panels)\n• 🌐 Websites Maintenance (Full-stack web application support, uptime monitoring & security)\n• 💻 Software Installations and Updates (OS deployment, patch rollouts & baseline maintenance)\n• ⚙️ Hardware Performance Maintenance (Diagnostics, thermal servicing & hardware tuning)"
  },
  {
    id: "faq-contact-support",
    category: "Services & Technical Support",
    question: "How can I contact technical support or request a service quotation?",
    answer: "You can reach our engineering and support team directly via:\n• 📞 Phone / WhatsApp: +254704393504\n• ✉️ Email: rogersiru@gmail.com\nWe are available for technical assistance, remote management, and onsite deployments."
  }
];

export const FAQ_CATEGORIES = [
  "All",
  "Device Admission & Security",
  "Access Schedules & Time Controls",
  "System Performance & Monitoring",
  "Endpoint Patching & Health",
  "Firewalls & Infrastructure",
  "Services & Technical Support"
];
