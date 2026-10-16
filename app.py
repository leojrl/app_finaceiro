from __future__ import annotations

import logging
import os
import re
import secrets
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import bcrypt
import firebase_admin
import streamlit as st
from firebase_admin import credentials, firestore
from google.api_core.exceptions import GoogleAPICallError
from streamlit.errors import StreamlitSecretNotFoundError


LOGGER = logging.getLogger(__name__)
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
MAX_AMOUNT_CENTS = 999_999_999_999


def validate_username(value: str) -> str:
    username = value.strip().lower()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Use de 3 a 32 caracteres: letras, números, ponto, hífen ou _.")
    return username


def validate_password(value: str) -> None:
    encoded_password = value.encode("utf-8")
    if len(value) < 8:
        raise ValueError("A senha deve ter pelo menos 8 caracteres.")
    if len(encoded_password) > 72:
        raise ValueError("A senha deve ter no máximo 72 bytes em UTF-8.")


def parse_amount(value: str) -> int:
    normalized = value.strip().replace(",", ".")
    try:
        amount = Decimal(normalized)
    except InvalidOperation as error:
        raise ValueError("Informe um valor válido, por exemplo 125,50.") from error

    if not amount.is_finite() or amount <= 0:
        raise ValueError("O valor deve ser maior que zero.")
    if amount.as_tuple().exponent < -2:
        raise ValueError("Informe no máximo duas casas decimais.")
    if amount > Decimal(MAX_AMOUNT_CENTS) / 100:
        raise ValueError("O valor informado excede o limite permitido.")

    cents = int(amount * 100)
    return cents


def get_firestore_client() -> firestore.Client:
    credentials_path = os.environ.get("FIREBASE_CREDENTIALS")
    try:
        firebase_config = st.secrets.get("firebase")
    except StreamlitSecretNotFoundError:
        firebase_config = None
    if credentials_path:
        credential_file = Path(credentials_path).expanduser()
        if not credential_file.is_file():
            raise RuntimeError(
                f"O arquivo de credenciais informado não existe: {credential_file}"
            )
        firebase_credential = credentials.Certificate(str(credential_file))
    elif firebase_config:
        firebase_credential = credentials.Certificate(dict(firebase_config))
    else:
        app_directory = Path(__file__).resolve().parent
        candidates = list(app_directory.glob("*firebase-adminsdk*.json"))
        standard_path = app_directory / "serviceAccountKey.json"
        if standard_path.is_file():
            candidates.append(standard_path)

        if len(candidates) > 1:
            raise RuntimeError(
                "Foram encontrados vários arquivos JSON de conta de serviço. "
                "Defina FIREBASE_CREDENTIALS com o caminho do arquivo correto."
            )
        if not candidates:
            raise RuntimeError(
                "Não encontrei um JSON de conta de serviço ao lado de app.py. "
                "Coloque o arquivo Firebase nessa pasta ou configure FIREBASE_CREDENTIALS "
                "com o caminho completo do JSON."
            )
        credential_file = candidates[0]
        firebase_credential = credentials.Certificate(str(credential_file))

    try:
        app = firebase_admin.get_app()
    except ValueError:
        app = firebase_admin.initialize_app(firebase_credential)
    return firestore.client(app=app)


def register_user(
    db: firestore.Client, username: str, password_hash: str, display_name: str
) -> bool:
    uid = secrets.token_urlsafe(24)
    username_ref = db.collection("usernames").document(username)
    user_ref = db.collection("users").document(uid)
    transaction = db.transaction()

    @firestore.transactional
    def create_account(transaction: Any) -> bool:
        username_snapshot = username_ref.get(transaction=transaction)
        if username_snapshot.exists:
            return False

        transaction.create(
            username_ref,
            {"uid": uid, "created_at": datetime.now(timezone.utc)},
        )
        transaction.create(
            user_ref,
            {
                "username": username,
                "display_name": display_name,
                "password_hash": password_hash,
                "created_at": datetime.now(timezone.utc),
            },
        )
        return True

    return create_account(transaction)


def authenticate_user(db: firestore.Client, username: str, password: str) -> dict[str, str] | None:
    username_snapshot = db.collection("usernames").document(username).get()
    if not username_snapshot.exists:
        return None

    uid = username_snapshot.get("uid")
    if not isinstance(uid, str):
        raise RuntimeError("A conta está inconsistente. Entre em contato com o suporte.")
    user_snapshot = db.collection("users").document(uid).get()
    if not user_snapshot.exists:
        raise RuntimeError("A conta está inconsistente. Entre em contato com o suporte.")

    user_data = user_snapshot.to_dict()
    if user_data is None:
        raise RuntimeError("A conta está inconsistente. Entre em contato com o suporte.")
    password_hash = user_data.get("password_hash")
    if not isinstance(password_hash, str):
        raise RuntimeError("A conta está inconsistente. Entre em contato com o suporte.")
    if len(password.encode("utf-8")) > 72:
        return None
    try:
        password_matches = bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise RuntimeError("A conta está inconsistente. Entre em contato com o suporte.") from error
    if not password_matches:
        return None

    stored_username = user_data.get("username")
    display_name = user_data.get("display_name")
    if not isinstance(stored_username, str) or not isinstance(display_name, str):
        raise RuntimeError("A conta está inconsistente. Entre em contato com o suporte.")
    return {"uid": uid, "username": stored_username, "display_name": display_name}


def list_transactions(db: firestore.Client, uid: str) -> list[dict[str, Any]]:
    records = []
    for snapshot in db.collection("transactions").where("owner_uid", "==", uid).stream():
        record = snapshot.to_dict()
        record["id"] = snapshot.id
        records.append(record)
    return sorted(records, key=lambda item: (item["date"], item["created_at"]), reverse=True)


def save_transaction(
    db: firestore.Client,
    uid: str,
    transaction_id: str | None,
    transaction_data: dict[str, Any],
) -> None:
    collection = db.collection("transactions")
    if transaction_id is None:
        transaction_data["owner_uid"] = uid
        transaction_data["created_at"] = datetime.now(timezone.utc)
        collection.document().create(transaction_data)
        return

    transaction_ref = collection.document(transaction_id)
    transaction = db.transaction()

    @firestore.transactional
    def update_owned_transaction(transaction: Any) -> None:
        snapshot = transaction_ref.get(transaction=transaction)
        if not snapshot.exists or snapshot.get("owner_uid") != uid:
            raise PermissionError("Lançamento não encontrado para este usuário.")
        transaction.update(transaction_ref, transaction_data)

    update_owned_transaction(transaction)


def delete_transaction(db: firestore.Client, uid: str, transaction_id: str) -> None:
    transaction_ref = db.collection("transactions").document(transaction_id)
    transaction = db.transaction()

    @firestore.transactional
    def delete_owned_transaction(transaction: Any) -> None:
        snapshot = transaction_ref.get(transaction=transaction)
        if not snapshot.exists or snapshot.get("owner_uid") != uid:
            raise PermissionError("Lançamento não encontrado para este usuário.")
        transaction.delete(transaction_ref)

    delete_owned_transaction(transaction)


def report_database_error(action: str, error: Exception) -> None:
    LOGGER.exception("Falha ao %s no Firebase", action, exc_info=error)
    st.error(f"Não foi possível {action}. Verifique a conexão com o Firebase e tente novamente.")


def money(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    whole, fractional = divmod(abs(cents), 100)
    formatted_whole = f"{whole:,}".replace(",", ".")
    return f"{sign}R$ {formatted_whole},{fractional:02d}"


def month_label(month_key: str) -> str:
    month_names = (
        "janeiro", "fevereiro", "março", "abril", "maio", "junho",
        "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
    )
    year, month = month_key.split("-")
    return f"{month_names[int(month) - 1].capitalize()} de {year}"


def render_authentication(db: firestore.Client) -> None:
    st.markdown(
        '<div class="brand"><div class="brand-mark">R$</div>'
        "<h1>Minhas finanças</h1><p>Seu dinheiro, mais organizado.</p></div>",
        unsafe_allow_html=True,
    )
    auth_mode = st.session_state.get("auth_mode", "login")
    st.caption("Acesse sua conta ou crie um cadastro para começar.")
    login_col, register_col = st.columns(2)
    with login_col:
        if st.button(
            "Entrar",
            key="auth_login",
            type="primary" if auth_mode == "login" else "secondary",
            use_container_width=True,
        ):
            st.session_state["auth_mode"] = "login"
            st.rerun()
    with register_col:
        if st.button(
            "Criar conta",
            key="auth_register",
            type="primary" if auth_mode == "register" else "secondary",
            use_container_width=True,
        ):
            st.session_state["auth_mode"] = "register"
            st.rerun()

    if auth_mode == "login":
        auth_message = st.session_state.pop("auth_message", None)
        if auth_message:
            st.success(auth_message)
        with st.container(border=True):
            st.subheader("Bem-vindo de volta")
            st.caption("Entre com seu usuário e senha.")
            with st.form("login_form"):
                username_input = st.text_input("Usuário", autocomplete="username", max_chars=32)
                password = st.text_input(
                    "Senha", type="password", autocomplete="current-password", max_chars=72
                )
                submitted = st.form_submit_button("Entrar", use_container_width=True)
        if submitted:
            try:
                username = validate_username(username_input)
                user = authenticate_user(db, username, password)
                if user is None:
                    st.error("Usuário ou senha incorretos.")
                else:
                    st.session_state["user"] = user
                    st.session_state["page"] = "home"
                    st.rerun()
            except ValueError as error:
                st.error(str(error))
            except (GoogleAPICallError, RuntimeError) as error:
                report_database_error("entrar", error)

    else:
        with st.container(border=True):
            st.subheader("Criar sua conta")
            st.caption("Preencha os dois campos para começar a organizar suas finanças.")
            with st.form("register_form"):
                new_username_input = st.text_input(
                    "Usuário",
                    autocomplete="username",
                    max_chars=32,
                    help="De 3 a 32 caracteres: letras, números, ponto, hífen ou _.",
                )
                new_password = st.text_input(
                    "Senha",
                    type="password",
                    autocomplete="new-password",
                    max_chars=72,
                    help="Use pelo menos 8 caracteres.",
                )
                submitted = st.form_submit_button("Cadastrar", use_container_width=True)
        if submitted:
            try:
                username = validate_username(new_username_input)
                validate_password(new_password)
                password_hash = bcrypt.hashpw(
                    new_password.encode("utf-8"), bcrypt.gensalt()
                ).decode("ascii")
                if register_user(db, username, password_hash, username):
                    st.session_state["auth_mode"] = "login"
                    st.session_state["auth_message"] = "Conta criada! Entre com seu usuário e senha."
                    st.rerun()
                else:
                    st.error("Esse usuário já está em uso.")
            except ValueError as error:
                st.error(str(error))
            except (GoogleAPICallError, RuntimeError) as error:
                report_database_error("criar a conta", error)


def render_transaction_form(
    db: firestore.Client,
    user: dict[str, str],
    transaction: dict[str, Any] | None = None,
    salary_entry: bool = False,
) -> None:
    is_editing = transaction is not None
    page_title = (
        "Editar lançamento" if is_editing
        else "Adicionar salário" if salary_entry
        else "Novo lançamento"
    )
    st.subheader(page_title)
    form_key = (
        f"transaction_form_{transaction['id']}" if is_editing
        else "transaction_form_salary" if salary_entry
        else "transaction_form_new"
    )
    initial_amount = f"{transaction['amount_cents'] / 100:.2f}".replace(".", ",") if is_editing else ""

    with st.form(form_key):
        transaction_type = st.selectbox(
            "Tipo",
            ["receita", "despesa"],
            index=(
                0 if salary_entry or not is_editing or transaction["type"] == "receita" else 1
            ),
            format_func=lambda value: "Receita" if value == "receita" else "Despesa",
            key=f"{form_key}_type",
        )
        description = st.text_input(
            "Descrição",
            value=transaction["description"] if is_editing else "Salário" if salary_entry else "",
            max_chars=100,
            key=f"{form_key}_description",
        )
        amount_text = st.text_input(
            "Valor (R$)",
            value=initial_amount,
            placeholder="Ex.: 125,50",
            max_chars=15,
            key=f"{form_key}_amount",
        )
        category = st.text_input(
            "Categoria",
            value=transaction["category"] if is_editing else "Salário" if salary_entry else "",
            max_chars=40,
            placeholder="Ex.: Alimentação",
            key=f"{form_key}_category",
        )
        transaction_date = st.date_input(
            "Data",
            value=date.fromisoformat(transaction["date"]) if is_editing else date.today(),
            key=f"{form_key}_date",
        )
        submit_label = (
            "Salvar alterações" if is_editing
            else "Salvar salário" if salary_entry
            else "Salvar lançamento"
        )
        save_clicked = st.form_submit_button(submit_label, use_container_width=True)

    if st.button("Voltar", key=f"{form_key}_back", use_container_width=True):
        st.session_state["page"] = "home"
        st.rerun()

    if save_clicked:
        try:
            clean_description = description.strip()
            clean_category = category.strip()
            if not clean_description:
                raise ValueError("Informe uma descrição.")
            if not clean_category:
                raise ValueError("Informe uma categoria.")
            transaction_data = {
                "type": transaction_type,
                "description": clean_description,
                "amount_cents": parse_amount(amount_text),
                "category": clean_category,
                "date": transaction_date.isoformat(),
            }
            save_transaction(db, user["uid"], transaction["id"] if is_editing else None, transaction_data)
            st.session_state["page"] = "home"
            st.session_state["saved_message"] = (
                "Salário salvo como receita." if salary_entry else "Lançamento salvo."
            )
            st.rerun()
        except ValueError as error:
            st.error(str(error))
        except PermissionError as error:
            st.error(str(error))
        except (GoogleAPICallError, RuntimeError) as error:
            report_database_error("salvar o lançamento", error)


def render_home(db: firestore.Client, user: dict[str, str]) -> None:
    try:
        records = list_transactions(db, user["uid"])
    except (GoogleAPICallError, KeyError, TypeError) as error:
        report_database_error("consultar os lançamentos", error)
        return

    st.sidebar.title("Minhas finanças")
    st.sidebar.caption(f"Conta: {user['username']}")
    st.sidebar.divider()
    if st.sidebar.button("Visão geral", use_container_width=True):
        st.session_state["page"] = "home"
        st.rerun()
    if st.sidebar.button("＋  Adicionar salário", use_container_width=True):
        st.session_state["page"] = "salary"
        st.rerun()
    if st.sidebar.button("＋  Adicionar lançamento", use_container_width=True):
        st.session_state["page"] = "create"
        st.rerun()

    available_months = sorted(
        {item["date"][:7] for item in records if isinstance(item.get("date"), str)},
        reverse=True,
    )
    current_month = date.today().strftime("%Y-%m")
    if current_month not in available_months:
        available_months.insert(0, current_month)
    month_options = ["Todos os meses", *available_months]
    if st.session_state.get("selected_month") not in month_options:
        st.session_state["selected_month"] = current_month
    selected_month = st.sidebar.selectbox(
        "Mês",
        month_options,
        format_func=lambda value: value if value == "Todos os meses" else month_label(value),
        key="selected_month",
    )

    if selected_month == "Todos os meses":
        displayed_records = records
        period_label = "Todos os meses"
    else:
        displayed_records = [item for item in records if item["date"].startswith(selected_month)]
        period_label = month_label(selected_month)

    categories = sorted({item["category"] for item in displayed_records})
    with st.sidebar.expander("Filtrar lançamentos", expanded=False):
        selected_type = st.selectbox(
            "Tipo",
            ["Todos", "Receitas", "Despesas"],
            key="transaction_type_filter",
        )
        selected_categories = st.multiselect(
            "Categorias",
            categories,
            default=[],
            placeholder="Todas as categorias",
            key="transaction_category_filter",
        )

    filtered_records = displayed_records
    if selected_type == "Receitas":
        filtered_records = [item for item in filtered_records if item["type"] == "receita"]
    elif selected_type == "Despesas":
        filtered_records = [item for item in filtered_records if item["type"] == "despesa"]
    if selected_categories:
        filtered_records = [
            item for item in filtered_records if item["category"] in selected_categories
        ]

    if st.session_state.get("saved_message"):
        st.success(st.session_state.pop("saved_message"))

    st.markdown(f"## Olá, {user['display_name'].split()[0]} 👋")
    st.caption(f"Seu panorama financeiro · {period_label}")

    income_total = sum(
        item["amount_cents"] for item in displayed_records if item["type"] == "receita"
    )
    expense_total = sum(
        item["amount_cents"] for item in displayed_records if item["type"] == "despesa"
    )
    balance = income_total - expense_total

    income_col, expense_col, balance_col = st.columns(3)
    with income_col:
        st.metric("Receitas", money(income_total))
    with expense_col:
        st.metric("Despesas", money(expense_total))
    with balance_col:
        st.metric("Saldo", money(balance))
    if income_total:
        committed_share = expense_total / income_total
        st.markdown("**Renda comprometida com despesas**")
        st.progress(min(committed_share, 1.0))
        st.caption(f"{committed_share:.0%} da receita deste período")

    expenses_by_category: dict[str, float] = {}
    for item in filtered_records:
        if item["type"] == "despesa":
            expenses_by_category[item["category"]] = (
                expenses_by_category.get(item["category"], 0) + item["amount_cents"] / 100
            )
    chart_col, tips_col = st.columns([3, 2])
    with chart_col:
        st.markdown("### Despesas por categoria")
        if expenses_by_category:
            st.bar_chart(
                {
                    "Categoria": list(expenses_by_category),
                    "Gastos (R$)": list(expenses_by_category.values()),
                },
                x="Categoria",
                y="Gastos (R$)",
                height=260,
            )
        else:
            st.caption("Sem despesas para os filtros selecionados.")
    with tips_col:
        st.markdown("### Visão rápida")
        st.metric("Lançamentos no período", len(displayed_records))
        highest_expense = max(expenses_by_category.items(), key=lambda item: item[1], default=None)
        if highest_expense:
            st.metric("Maior categoria de gasto", highest_expense[0], money(round(highest_expense[1] * 100)))
        else:
            st.info("Adicione despesas para ver seus principais gastos.")

    st.markdown("### Lançamentos")
    st.caption(f"{len(filtered_records)} item(ns) com os filtros atuais.")
    if not filtered_records:
        st.info("Não há lançamentos neste período. Use o menu para adicionar salário ou despesa.")

    for record in filtered_records:
        is_income = record["type"] == "receita"
        sign = "+" if is_income else "−"
        amount_class = "income" if is_income else "expense"
        with st.container(border=True):
            detail_col, amount_col = st.columns([3, 2])
            with detail_col:
                st.markdown(f"**{record['description']}**")
                st.caption(
                    f"{record['category']} · "
                    f"{date.fromisoformat(record['date']).strftime('%d/%m/%Y')}"
                )
            with amount_col:
                st.markdown(
                    f'<div class="amount {amount_class}">{sign} {money(record["amount_cents"])}</div>',
                    unsafe_allow_html=True,
                )

            edit_col, delete_col = st.columns(2)
            with edit_col:
                if st.button("Editar", key=f"edit_{record['id']}", use_container_width=True):
                    st.session_state["editing_transaction"] = record
                    st.session_state["page"] = "edit"
                    st.rerun()
            with delete_col:
                delete_key = f"confirm_delete_{record['id']}"
                if st.session_state.get("delete_transaction_id") == record["id"]:
                    if st.button("Confirmar exclusão", key=delete_key, use_container_width=True):
                        try:
                            delete_transaction(db, user["uid"], record["id"])
                            st.session_state.pop("delete_transaction_id", None)
                            st.success("Lançamento excluído.")
                            st.rerun()
                        except PermissionError as error:
                            st.error(str(error))
                        except GoogleAPICallError as error:
                            report_database_error("excluir o lançamento", error)
                    if st.button("Cancelar", key=f"cancel_{record['id']}", use_container_width=True):
                        st.session_state.pop("delete_transaction_id", None)
                        st.rerun()
                elif st.button("Excluir", key=f"delete_{record['id']}", use_container_width=True):
                    st.session_state["delete_transaction_id"] = record["id"]
                    st.rerun()

    if st.button("+", key="add_transaction", help="Adicionar lançamento"):
        st.session_state["page"] = "create"
        st.rerun()


def logout() -> None:
    for key in (
        "user",
        "page",
        "editing_transaction",
        "delete_transaction_id",
        "selected_month",
        "transaction_type_filter",
        "transaction_category_filter",
    ):
        st.session_state.pop(key, None)


def render_logout_button() -> None:
    st.button("Sair da conta", key="logout_button", on_click=logout)


def main() -> None:
    st.set_page_config(
        page_title="Minhas finanças",
        page_icon="💸",
        layout="centered",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
        :root { color-scheme: light; }
        .stApp { background: linear-gradient(135deg, #f4f7fb 0%, #f7f8fc 55%, #edf5f2 100%); font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
        .block-container { max-width: 1120px; padding: 2rem 1.5rem 7rem; }
        [data-testid="stSidebar"] { background: #f0f4f7; border-right: 1px solid #e1e8ed; }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h1 { color: #126b55; font-size: 1.35rem; }
        [data-testid="stSidebar"] div.stButton > button { text-align: left; }
        [data-testid="stMetric"] {
            background: rgba(255,255,255,.9); border: 1px solid #e5ebf1; border-radius: 18px;
            padding: 18px 16px; min-height: 104px; box-shadow: 0 8px 24px #1f3b4d0a;
        }
        [data-testid="stMetricLabel"] { font-size: .78rem; }
        [data-testid="stMetricValue"] { font-size: clamp(1rem, 4vw, 1.45rem); }
        .brand { text-align: center; padding: 2rem 0 1.3rem; }
        .brand h1 { margin: .5rem 0 .2rem; }
        .brand p { color: #687386; }
        .brand-mark {
            width: 58px; height: 58px; border-radius: 18px; background: #126b55;
            color: white; display: inline-flex; align-items: center; justify-content: center;
            font-weight: 700; font-size: 1.2rem;
        }
        .amount { text-align: right; font-weight: 700; padding-top: .4rem; }
        .income { color: #14805e; }
        .expense { color: #d64b58; }
        div[data-testid="stHorizontalBlock"] { gap: .55rem; }
        div.stButton > button { border-radius: 13px; min-height: 44px; transition: all .18s ease; }
        div.stButton > button[kind="primary"] { background: #126b55; border-color: #126b55; }
        div.stButton > button:hover { border-color: #126b55; color: #126b55; transform: translateY(-1px); }
        .st-key-add_transaction {
            position: fixed; bottom: max(1.25rem, env(safe-area-inset-bottom));
            left: 50%; transform: translateX(-50%); z-index: 1000;
        }
        .st-key-add_transaction button {
            width: 64px; height: 64px; border-radius: 50% !important; padding: 0;
            background: #126b55 !important; color: white !important;
            border: 0 !important; box-shadow: 0 8px 22px #126b5540; font-size: 2rem;
        }
        .st-key-logout_button {
            position: fixed; right: max(1.25rem, env(safe-area-inset-right));
            bottom: max(1.25rem, env(safe-area-inset-bottom)); z-index: 1001;
        }
        .st-key-logout_button button {
            min-height: 46px; border-radius: 24px; padding: 0 20px;
            background: #fff; border: 1px solid #e1e8ed; color: #44515c;
            box-shadow: 0 8px 22px #1f3b4d1a;
        }
        .st-key-logout_button button:hover { background: #fff; color: #b42332; border-color: #e8a1a8; }
        @media (max-width: 480px) {
            .block-container { padding: 1rem .8rem 7rem; }
            [data-testid="stMetric"] { padding: 11px 8px; min-height: 84px; }
            .st-key-logout_button { right: .7rem; bottom: .8rem; }
            .st-key-logout_button button { min-height: 42px; padding: 0 14px; }
            .st-key-add_transaction { left: 42%; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    try:
        db = get_firestore_client()
    except (FileNotFoundError, RuntimeError, ValueError, firebase_admin.exceptions.FirebaseError) as error:
        st.error(f"Configuração do Firebase inválida: {error}")
        st.stop()

    user = st.session_state.get("user")
    if not user:
        render_authentication(db)
        return

    page = st.session_state.get("page", "home")
    if page == "create":
        render_transaction_form(db, user)
    elif page == "salary":
        render_transaction_form(db, user, salary_entry=True)
    elif page == "edit":
        transaction = st.session_state.get("editing_transaction")
        if transaction is None:
            st.session_state["page"] = "home"
            st.rerun()
        render_transaction_form(db, user, transaction)
    else:
        render_home(db, user)
    render_logout_button()


if __name__ == "__main__":
    main()
