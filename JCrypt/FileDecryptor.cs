//sha256: bb0bca92cc74cac6b770649c5e70b0f4fd177de58fcfc7c719223485624dc28b
using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

static class Constants
{ 
	public const string pword = "Password1";
}


public class Program
{
	public static void Main()
	{
		
		string DESKTOP_FOLDER = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
		string DOCUMENTS_FOLDER = Environment.GetFolderPath(Environment.SpecialFolder.Personal);
		string PICTURES_FOLDER = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
		FileDecryptor(DESKTOP_FOLDER);
		FileDecryptor(DOCUMENTS_FOLDER);
		FileDecryptor(PICTURES_FOLDER);
		
	}
	public static void Decrypt(string inputFile, string outputFile, string password)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(password);
		byte[] array = new byte[32];
		FileStream fileStream = new FileStream(inputFile, FileMode.Open);
		fileStream.Read(array, 0, array.Length);
		RijndaelManaged rijndaelManaged = new RijndaelManaged();
		rijndaelManaged.KeySize = 256;
		rijndaelManaged.BlockSize = 128;
		Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(bytes, array, 50000);
		rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
		rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
		rijndaelManaged.Padding = PaddingMode.PKCS7;
		rijndaelManaged.Mode = CipherMode.CBC;
		CryptoStream cryptoStream = new CryptoStream(fileStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Read);
		FileStream fileStream2 = new FileStream(outputFile, FileMode.Create);
		byte[] array2 = new byte[1048576];
		try
		{
			int count;
			while ((count = cryptoStream.Read(array2, 0, array2.Length)) > 0)
			{
				fileStream2.Write(array2, 0, count);
			}
		}
		catch (CryptographicException ex)
		{
			Console.WriteLine("CryptographicException error: " + ex.Message);
		}
		catch (Exception ex2)
		{
			Console.WriteLine("Error: " + ex2.Message);
		}
		try
		{
			cryptoStream.Close();
		}
		catch (Exception ex3)
		{
			Console.WriteLine("Error by closing CryptoStream: " + ex3.Message);
		}
		finally
		{
			fileStream2.Close();
			fileStream.Close();
		}
	}
	public static void FileDecryptor(string sDir)
	{
		try
		{
			foreach (string text in Directory.GetFiles(sDir))
			{
				bool flag = text.Contains(".JEBAĆ_BYDGOSZCZ!!!");
				if (flag)
				{
					string extension = Path.GetExtension(text);
					string result = text.Substring(0, text.Length - extension.Length);
					Decrypt(text,result,Constants.pword);
					File.Delete(text);
					//Console.WriteLine(text);
				}
			}
			foreach (string sDir2 in Directory.GetDirectories(sDir))
			{
				FileDecryptor(sDir2);
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine(ex.Message);
		}
	}
	


}
