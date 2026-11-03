import json
import pandas as pd
import streamlit as st

# 1. 頁面配置
st.set_page_config(
    page_title="Cowrie 蜜罐威脅分析儀表板",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. 注入客製化 CSS（簡潔專業風 SaaS 控制台）
st.markdown("""
    <style>
    /* 全域背景：清爽淺灰 */
    .stApp {
        background-color: #f8fafc;
        color: #0f172a;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    
    /* 頂部 Header */
    .main-header {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-left: 5px solid #2563eb;
        padding: 16px 24px;
        border-radius: 8px;
        margin-bottom: 24px;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04);
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    
    .main-title {
        color: #0f172a;
        font-size: 1.4rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        margin: 0;
    }

    .subtitle {
        color: #64748b;
        font-size: 0.85rem;
        margin-top: 4px;
    }

    /* 狀態標籤 */
    .status-badge {
        background-color: #f0fdf4;
        color: #166534;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 600;
        border: 1px solid #bbf7d0;
    }

    /* 指標卡片 (Metric Cards) */
    div[data-testid="stMetric"] {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 14px 18px;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04);
    }
    
    div[data-testid="stMetric"] label {
        color: #64748b !important;
        font-size: 0.82rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #1e293b !important;
        font-size: 1.75rem !important;
        font-weight: 700 !important;
    }

    /* 區塊標題 */
    .stMarkdown h3 {
        color: #0f172a !important;
        font-size: 1.1rem !important;
        font-weight: 700 !important;
        margin-top: 6px !important;
        margin-bottom: 14px !important;
    }

    /* 標籤頁 (Tabs) 樣式美化 */
    button[data-baseweb="tab"] {
        font-size: 0.95rem !important;
        font-weight: 600 !important;
        color: #64748b !important;
    }

    button[aria-selected="true"] {
        color: #2563eb !important;
    }
    </style>
""", unsafe_allow_html=True)

# 3. 讀取日誌
log_file = "cowrie.json"
data = []

try:
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # 判斷是否為 JSON 格式（以 { 開頭並以 } 結尾）
            if line.startswith("{") and line.endswith("}"):
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # 若解析失敗則自動跳過該行
                    
    if not data:
        st.warning("⚠️ 檔案中未發現任何有效的 JSON 日誌數據！")
        st.stop()
        
    df = pd.DataFrame(data)
except FileNotFoundError:
    st.error(f"找不到 `{log_file}` 檔案，請確認檔案與 app.py 放在同一個目錄下。")
    st.stop()
except Exception as e:
    st.error(f"解析失敗：{e}")
    st.stop()

# 頂部 Banner
st.markdown("""
    <div class="main-header">
        <div>
            <div class="main-title">Cowrie 蜜罐威脅即時監控儀表板</div>
            <div class="subtitle">即時捕獲入侵行為 / 密碼爆破統計 / 攻擊指令歷程分析</div>
        </div>
        <div>
            <span class="status-badge">系統監控中 (LIVE)</span>
        </div>
    </div>
""", unsafe_allow_html=True)

# 側邊欄 (Sidebar)
with st.sidebar:
    st.markdown("### 控制台設定")
    st.markdown("---")
    top_n = st.slider("排行榜顯示數量", min_value=3, max_value=10, value=5)
    st.markdown("---")

# 數據計算
total_logs = len(df)
unique_ips = df["src_ip"].nunique() if "src_ip" in df.columns else 0
login_df = df[df["eventid"].str.contains("login", na=False)] if "eventid" in df.columns else pd.DataFrame()
total_logins = len(login_df)
success_logins = len(df[df["eventid"] == "cowrie.login.success"]) if "eventid" in df.columns else 0

# 4. 頂部 KPI 卡片
c1, c2, c3, c4 = st.columns(4)
c1.metric("日誌紀錄總筆數", f"{total_logs:,}")
c2.metric("攻擊來源 IP 數", f"{unique_ips}")
c3.metric("密碼爆破嘗試次數", f"{total_logins}")
c4.metric("成功侵入次數", f"{success_logins}")

st.markdown("<br>", unsafe_allow_html=True)

# 5. 頁籤分類
tab1, tab2, tab3 = st.tabs(["威脅特徵統計", "終端機指令歷程", "原始日誌明細"])

with tab1:
    col_left, col_right = st.columns([1, 1])
    
    with col_left:
        st.subheader(f"被嘗試最多次的密碼 Top {top_n}")
        if "password" in df.columns and not df["password"].dropna().empty:
            pwd_counts = (
                df[df["password"].notna()]["password"]
                .value_counts()
                .head(top_n)
                .reset_index()
            )
            pwd_counts.columns = ["密碼", "嘗試次數"]
            st.bar_chart(pwd_counts.set_index("密碼"), color="#2563eb")
        else:
            st.info("尚無登入密碼相關數據")

    with col_right:
        st.subheader("攻擊來源 IP 活躍度排名")
        if "src_ip" in df.columns:
            ip_counts = df["src_ip"].value_counts().reset_index()
            ip_counts.columns = ["來源 IP", "活動次數"]
            st.dataframe(
                ip_counts,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "活動次數": st.column_config.ProgressColumn(
                        "活動次數",
                        format="%d",
                        min_value=0,
                        max_value=int(ip_counts["活動次數"].max() if not ip_counts.empty else 10),
                    ),
                }
            )

with tab2:
    st.subheader("攻擊者侵入後執行的 Terminal 指令")
    if "eventid" in df.columns:
        cmd_df = df[df["eventid"] == "cowrie.command.input"]
        if not cmd_df.empty and "input" in cmd_df.columns:
            cmd_display = cmd_df[["timestamp", "src_ip", "input"]].rename(
                columns={
                    "timestamp": "時間 (Timestamp)",
                    "src_ip": "來源 IP",
                    "input": "執行的指令 (Executed Command)"
                }
            )
            st.dataframe(
                cmd_display,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "執行的指令 (Executed Command)": st.column_config.TextColumn(
                        "執行的指令 (Executed Command)",
                        help="攻擊者連入後輸入的 Bash 指令",
                        width="large"
                    )
                }
            )
        else:
            st.info("目前尚未捕獲到指令輸入事件。")

with tab3:
    st.subheader("原始日誌過濾與查詢")
    if "eventid" in df.columns:
        event_types = ["全部 (ALL)"] + list(df["eventid"].unique())
        selected_event = st.selectbox("篩選事件類型 (Event ID)", event_types)
        
        filtered_df = df if selected_event == "全部 (ALL)" else df[df["eventid"] == selected_event]
        st.dataframe(filtered_df, use_container_width=True, hide_index=True)