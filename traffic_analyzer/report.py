"""HTML and CSV report generation."""

from __future__ import annotations

import csv
import html
from collections import Counter
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from .analyzer import AnalysisResult
from .packets import tcp_flag_names


def format_bytes(number: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(number)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            if unit == "B":
                return "{} {}".format(int(value), unit)
            return "{:.2f} {}".format(value, unit)
        value /= 1024.0
    return "{} B".format(number)


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "{:.0f} ms".format(seconds * 1000)
    if seconds < 60:
        return "{:.2f} s".format(seconds)
    minutes, rest = divmod(seconds, 60)
    if minutes < 60:
        return "{:.0f} min {:.1f} s".format(minutes, rest)
    hours, minutes = divmod(minutes, 60)
    return "{:.0f} h {:.0f} min".format(hours, minutes)


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _bar_rows(counter: Counter, limit: int, unit: str = "") -> str:
    items = counter.most_common(limit)
    if not items:
        return '<tr><td colspan="3" class="empty">暂无数据</td></tr>'
    maximum = max(value for _, value in items) or 1
    rows = []
    for name, value in items:
        percent = value / maximum * 100
        rows.append(
            "<tr><td>{}</td><td>{}{}</td><td>"
            '<div class="bar-track"><span class="bar" style="width:{:.1f}%"></span></div>'
            "</td></tr>".format(
                _escape(name),
                _escape(value),
                _escape(unit),
                percent,
            )
        )
    return "\n".join(rows)


def _plain_rows(pairs: Iterable[Tuple[object, object]], empty_text: str = "暂无数据") -> str:
    rows = list(pairs)
    if not rows:
        return '<tr><td colspan="2" class="empty">{}</td></tr>'.format(
            _escape(empty_text)
        )
    return "\n".join(
        "<tr><td>{}</td><td>{}</td></tr>".format(_escape(left), _escape(right))
        for left, right in rows
    )


def _alert_html(result: AnalysisResult) -> str:
    if not result.alerts:
        return (
            '<div class="empty-state">未发现明显异常。'
            "当前规则覆盖端口扫描和 ICMP 流量异常。</div>"
        )
    cards = []
    for alert in result.alerts:
        severity = alert.severity.lower()
        cards.append(
            '<article class="alert {severity}">'
            '<div class="alert-head"><span class="badge">{severity}</span>'
            "<strong>{kind}</strong></div>"
            "<p>{message}</p><small>{evidence}</small></article>".format(
                severity=_escape(severity),
                kind=_escape(alert.kind),
                message=_escape(alert.message),
                evidence=_escape(alert.evidence),
            )
        )
    return "\n".join(cards)


def _packet_rows(result: AnalysisResult, max_packets: int) -> str:
    if not result.packets:
        return '<tr><td colspan="6" class="empty">暂无数据</td></tr>'
    rows = []
    for index, packet in enumerate(result.packets[:max_packets], start=1):
        if packet.protocol == "TCP":
            extra = tcp_flag_names(packet.tcp_flags)
        elif packet.protocol == "ICMP":
            extra = "type={}".format(packet.icmp_type)
        else:
            extra = "-"
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                index,
                "{:.3f}".format(packet.timestamp),
                _escape(packet.src_endpoint),
                _escape(packet.dst_endpoint),
                _escape(packet.protocol),
                _escape(extra),
            )
        )
    return "\n".join(rows)


def generate_html(result: AnalysisResult, output_path: str, max_packets: int = 200) -> None:
    protocols = _bar_rows(result.protocols, 10)
    sources = _bar_rows(result.src_ips, 10)
    destinations = _bar_rows(result.dst_ips, 10)
    ports = _bar_rows(result.dst_ports, 10)
    flags = _plain_rows(
        (tcp_flag_names(flag), count)
        for flag, count in result.tcp_flags.most_common(12)
    )
    icmp_types = _plain_rows(
        ("type={}".format(icmp_type), count)
        for icmp_type, count in result.icmp_types.most_common(10)
    )

    html_text = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>网络流量分析报告</title>
  <style>
    :root {{
      --bg: #f4f7fb;
      --panel: #ffffff;
      --ink: #162033;
      --muted: #5d6b82;
      --line: #dce5f0;
      --blue: #225ea8;
      --teal: #0f8b8d;
      --orange: #d97706;
      --red: #c24141;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
      line-height: 1.55;
    }}
    header {{
      background: linear-gradient(120deg, #123b70, #0f8b8d);
      color: white;
      padding: 34px 28px;
    }}
    header h1 {{ margin: 0 0 8px; font-size: 28px; }}
    header p {{ margin: 0; opacity: .88; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      box-shadow: 0 8px 24px rgba(28, 44, 70, .05);
    }}
    .card .label {{ color: var(--muted); font-size: 13px; }}
    .card .value {{ font-size: 25px; font-weight: 700; margin-top: 4px; }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 18px;
    }}
    h2 {{ margin: 0 0 14px; font-size: 18px; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 8px 6px; border-bottom: 1px solid #edf1f6; vertical-align: middle; }}
    th {{ color: var(--muted); font-size: 12px; font-weight: 600; }}
    td {{ font-size: 13px; }}
    .bar-track {{ background: #e9eff7; height: 8px; border-radius: 99px; overflow: hidden; min-width: 90px; }}
    .bar {{ display: block; height: 100%; background: linear-gradient(90deg, var(--blue), var(--teal)); }}
    .empty, .empty-state {{ color: var(--muted); padding: 14px 0; }}
    .alert {{
      border-left: 4px solid var(--orange);
      background: #fff9ef;
      padding: 12px 14px;
      border-radius: 6px;
      margin-bottom: 10px;
    }}
    .alert.high {{ border-left-color: var(--red); background: #fff1f1; }}
    .alert.medium {{ border-left-color: var(--orange); }}
    .alert-head {{ display: flex; align-items: center; gap: 9px; margin-bottom: 5px; }}
    .badge {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: .04em;
      padding: 2px 7px;
      border-radius: 99px;
      background: #123b70;
      color: #fff;
    }}
    .alert.high .badge {{ background: var(--red); }}
    .alert.medium .badge {{ background: var(--orange); }}
    .alert p {{ margin: 0 0 3px; }}
    .alert small {{ color: var(--muted); }}
    footer {{ color: var(--muted); text-align: center; padding: 12px 20px 30px; font-size: 12px; }}
    @media (max-width: 820px) {{
      .cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .grid {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 520px) {{
      .cards {{ grid-template-columns: 1fr; }}
      main {{ padding: 14px; }}
      header {{ padding: 24px 18px; }}
    }}
  </style>
</head>
<body>
<header>
  <h1>网络流量分析报告</h1>
  <p>文件：{pcap_path} · 生成工具：network-traffic-analyzer</p>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="label">总数据包</div><div class="value">{total_packets}</div></div>
    <div class="card"><div class="label">总流量</div><div class="value">{total_bytes}</div></div>
    <div class="card"><div class="label">捕获时长</div><div class="value">{duration}</div></div>
    <div class="card"><div class="label">告警数量</div><div class="value">{alert_count}</div></div>
  </div>

  <section>
    <h2>异常告警</h2>
    {alerts}
  </section>

  <div class="grid">
    <section>
      <h2>协议分布</h2>
      <table><thead><tr><th>协议</th><th>数据包</th><th>占比</th></tr></thead><tbody>{protocols}</tbody></table>
    </section>
    <section>
      <h2>TCP 标志位</h2>
      <table><thead><tr><th>标志</th><th>数据包</th></tr></thead><tbody>{flags}</tbody></table>
    </section>
  </div>

  <div class="grid">
    <section>
      <h2>Top 源 IP</h2>
      <table><thead><tr><th>IP</th><th>数据包</th><th>相对量</th></tr></thead><tbody>{sources}</tbody></table>
    </section>
    <section>
      <h2>Top 目的 IP</h2>
      <table><thead><tr><th>IP</th><th>数据包</th><th>相对量</th></tr></thead><tbody>{destinations}</tbody></table>
    </section>
  </div>

  <div class="grid">
    <section>
      <h2>Top 目的端口</h2>
      <table><thead><tr><th>端口</th><th>数据包</th><th>相对量</th></tr></thead><tbody>{ports}</tbody></table>
    </section>
    <section>
      <h2>ICMP 类型</h2>
      <table><thead><tr><th>类型</th><th>数据包</th></tr></thead><tbody>{icmp_types}</tbody></table>
    </section>
  </div>

  <section>
    <h2>数据包预览（前 {max_packets} 条）</h2>
    <table>
      <thead><tr><th>#</th><th>时间</th><th>源</th><th>目的</th><th>协议</th><th>标志 / 类型</th></tr></thead>
      <tbody>{packet_rows}</tbody>
    </table>
  </section>
</main>
<footer>本报告由 network-traffic-analyzer 自动生成。仅用于授权网络、公开数据集或自有实验环境。</footer>
</body>
</html>
""".format(
        pcap_path=_escape(result.pcap_path),
        total_packets=result.total_packets,
        total_bytes=format_bytes(result.total_bytes),
        duration=format_duration(result.duration),
        alert_count=len(result.alerts),
        alerts=_alert_html(result),
        protocols=protocols,
        flags=flags,
        sources=sources,
        destinations=destinations,
        ports=ports,
        icmp_types=icmp_types,
        max_packets=max_packets,
        packet_rows=_packet_rows(result, max_packets),
    )
    Path(output_path).write_text(html_text, encoding="utf-8")


def generate_csv(result: AnalysisResult, output_path: str) -> None:
    with Path(output_path).open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["section", "key", "value"])
        writer.writerow(["overview", "pcap", result.pcap_path])
        writer.writerow(["overview", "packets", result.total_packets])
        writer.writerow(["overview", "bytes", result.total_bytes])
        writer.writerow(["overview", "duration_seconds", round(result.duration, 6)])
        writer.writerow(["overview", "alerts", len(result.alerts)])

        for name, count in result.protocols.most_common():
            writer.writerow(["protocol", name, count])
        for ip, count in result.src_ips.most_common(100):
            writer.writerow(["top_src_ip", ip, count])
        for ip, count in result.dst_ips.most_common(100):
            writer.writerow(["top_dst_ip", ip, count])
        for port, count in result.dst_ports.most_common(100):
            writer.writerow(["top_dst_port", port, count])
        for alert in result.alerts:
            writer.writerow(
                [
                    "alert",
                    alert.kind,
                    "{} | {} | {}".format(alert.src, alert.message, alert.evidence),
                ]
            )
