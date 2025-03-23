import brute
import sql_inject
import decrypt

if __name__ == "__main__":
    brute.brute_force_dvwa()
    sql_inject.perform_sql_injection()
    decrypt.decrypt_passwords()