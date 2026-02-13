"""Utility functions for database setup"""
import psycopg2
from psycopg2 import OperationalError as PgOperationalError
import json
import os
from pathlib import Path


def test_postgresql_connection(host, port, database, user, password):
    """
    Test PostgreSQL connection
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            connect_timeout=5
        )
        conn.close()
        return True, "Connection successful"
    except PgOperationalError as e:
        error_msg = str(e)
        if 'database' in error_msg and 'does not exist' in error_msg:
            # Try connecting to postgres database to create the target database
            try:
                conn = psycopg2.connect(
                    host=host,
                    port=port,
                    database='postgres',
                    user=user,
                    password=password,
                    connect_timeout=5
                )
                conn.close()
                return True, f"Connection successful (database '{database}' will be created)"
            except Exception as e2:
                return False, f"Connection failed: {str(e2)}"
        return False, f"Connection failed: {error_msg}"
    except Exception as e:
        return False, f"Connection failed: {str(e)}"


def create_postgresql_database(host, port, user, password, database_name):
    """
    Create PostgreSQL database
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Connect to postgres database
        conn = psycopg2.connect(
            host=host,
            port=port,
            database='postgres',
            user=user,
            password=password
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s",
            (database_name,)
        )
        exists = cursor.fetchone()
        
        if exists:
            cursor.close()
            conn.close()
            return True, f"Database '{database_name}' already exists"
        
        # Create database
        cursor.execute(f'CREATE DATABASE "{database_name}"')
        cursor.close()
        conn.close()
        
        return True, f"Database '{database_name}' created successfully"
    except Exception as e:
        return False, f"Failed to create database: {str(e)}"


def test_sqlserver_connection(host, port, database, user, password, windows_auth=False):
    """
    Test SQL Server connection
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        import pyodbc
        
        if windows_auth:
            conn_str = f"DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={host},{port};Trusted_Connection=yes;TrustServerCertificate=yes;"
        else:
            conn_str = f"DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={host},{port};UID={user};PWD={password};TrustServerCertificate=yes;"
        
        # Try to connect to the specific database
        try:
            conn = pyodbc.connect(conn_str + f"DATABASE={database};", timeout=5)
            conn.close()
            return True, "Connection successful"
        except pyodbc.Error as e:
            # If database doesn't exist, try connecting to master
            if 'Cannot open database' in str(e):
                try:
                    conn = pyodbc.connect(conn_str + "DATABASE=master;", timeout=5)
                    conn.close()
                    return True, f"Connection successful (database '{database}' will be created)"
                except Exception as e2:
                    return False, f"Connection failed: {str(e2)}"
            return False, f"Connection failed: {str(e)}"
    except ImportError:
        return False, "pyodbc module not installed. Please install it: pip install pyodbc"
    except Exception as e:
        return False, f"Connection failed: {str(e)}"


def create_sqlserver_database(host, port, user, password, database_name, windows_auth=False):
    """
    Create SQL Server database
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        import pyodbc
        
        if windows_auth:
            conn_str = (
                f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                f"SERVER={host},{port};"
                f"DATABASE=master;"
                f"Trusted_Connection=yes;"
                f"TrustServerCertificate=yes;"
            )
        else:
            conn_str = (
                f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                f"SERVER={host},{port};"
                f"DATABASE=master;"
                f"UID={user};"
                f"PWD={password};"
                f"TrustServerCertificate=yes;"
            )
        
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute(
            "SELECT database_id FROM sys.databases WHERE name = ?",
            (database_name,)
        )
        exists = cursor.fetchone()
        
        if exists:
            cursor.close()
            conn.close()
            return True, f"Database '{database_name}' already exists"
        
        # Create database
        cursor.execute(f"CREATE DATABASE [{database_name}]")
        conn.commit()
        cursor.close()
        conn.close()
        
        return True, f"Database '{database_name}' created successfully"
    except ImportError:
        return False, "pyodbc module not installed"
    except Exception as e:
        return False, f"Failed to create database: {str(e)}"


def save_database_config(config_dict, base_dir):
    """
    Save database configuration to .db_config.json
    
    Args:
        config_dict: Dictionary with database configuration
        base_dir: Base directory path
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        config_file = Path(base_dir) / '.db_config.json'
        with open(config_file, 'w') as f:
            json.dump(config_dict, f, indent=2)
        return True, "Configuration saved successfully"
    except Exception as e:
        return False, f"Failed to save configuration: {str(e)}"


def load_database_config(base_dir):
    """
    Load database configuration from .db_config.json
    
    Args:
        base_dir: Base directory path
    
    Returns:
        dict or None: Configuration dictionary or None if not found
    """
    try:
        config_file = Path(base_dir) / '.db_config.json'
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        return None
    except Exception:
        return None


def is_setup_complete(base_dir):
    """
    Check if setup is complete
    
    Args:
        base_dir: Base directory path
    
    Returns:
        bool: True if setup is complete
    """
    config = load_database_config(base_dir)
    return config is not None and config.get('setup_complete', False)
