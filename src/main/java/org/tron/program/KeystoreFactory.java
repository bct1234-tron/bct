package org.tron.program;

import com.beust.jcommander.JCommander;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tron.common.crypto.ECKey;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.Utils;
import org.tron.core.Constant;
import org.tron.core.config.args.Args;
import org.tron.core.services.http.Util;
import org.tron.keystore.CipherException;
import org.tron.keystore.Credentials;
import org.tron.keystore.WalletUtils;
import org.tron.program.command.KeyCommand;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;

@Slf4j(topic = "app")
public class KeystoreFactory {

	private static Logger LOGGER = LoggerFactory.getLogger(KeystoreFactory.class);
	private static final String FilePath = "Wallet";

	private static Map<String, Method> commandMap = new HashMap<>();

	static {
		Method[] methods = KeystoreFactory.class.getDeclaredMethods();
		for (Method m : methods) {
			KeyCommand anno = m.getAnnotation(KeyCommand.class);
			if (anno != null) {
				m.setAccessible(true);
				commandMap.put(anno.value().toLowerCase().trim(), m);
			}
		}
	}

	private boolean priKeyValid(String priKey) {
		if (StringUtils.isEmpty(priKey)) {
			logger.warn("Warning: PrivateKey is empty !!");
			return false;
		}
		if (priKey.length() != 64) {
			logger.warn("Warning: PrivateKey length need 64 but " + priKey.length() + " !!");
			return false;
		}
		//Other rule;
		return true;
	}

	@KeyCommand(value = "hexAddr", desc = "Show Hex Address")
	private void toHexAddr(String args[]) throws Throwable {
		System.out.println("Please Input Address:");
		Scanner in = null;
		String password;
		Console cons = System.console();
		if (cons == null) {
			in = new Scanner(System.in);
		}
		String addr = in.nextLine();
		System.out.println(Util.getHexAddress(addr));
	}

	@KeyCommand(value = "genKeystore", desc = "Create New Address")
	private void genKeystore(String args[]) throws CipherException, IOException {
		String password = WalletUtils.inputPassword2Twice();

		ECKey eCkey = new ECKey(Utils.random);
		File file = new File(FilePath);
		if (!file.exists()) {
			if (!file.mkdir()) {
				throw new IOException("Make directory faild!");
			}
		} else {
			if (!file.isDirectory()) {
				if (file.delete()) {
					if (!file.mkdir()) {
						throw new IOException("Make directory faild!");
					}
				} else {
					throw new IOException("File is exists and can not delete!");
				}
			}
		}
		String fileName = WalletUtils.generateWalletFile(password, eCkey, file, true);
		Credentials credentials = WalletUtils.loadCredentials(password, new File(file, fileName));
		printCredentialInfo(credentials);
	}

	@KeyCommand(value = "importprivatekey", desc = "Import Private Key")
	private void importPrivatekey(String[] args) throws CipherException, IOException {
		Scanner in = new Scanner(System.in);
		String privateKey;
		System.out.println("Please input private key.");
		while (true) {
			String input = in.nextLine().trim();
			privateKey = input.split("\\s+")[0];
			if (priKeyValid(privateKey)) {
				break;
			}
			System.out.println("Invalid private key, please input again.");
		}

		String password = WalletUtils.inputPassword2Twice();

		ECKey eCkey = ECKey.fromPrivate(ByteArray.fromHexString(privateKey));
		File file = new File(FilePath);
		if (!file.exists()) {
			if (!file.mkdir()) {
				throw new IOException("Make directory faild!");
			}
		} else {
			if (!file.isDirectory()) {
				if (file.delete()) {
					if (!file.mkdir()) {
						throw new IOException("Make directory faild!");
					}
				} else {
					throw new IOException("File is exists and can not delete!");
				}
			}
		}
		String fileName = WalletUtils.generateWalletFile(password, eCkey, file, true);
		Credentials credentials = WalletUtils.loadCredentials(password, new File(file, fileName));
		printCredentialInfo(credentials);

	}

	private void printCredentialInfo(Credentials credentials) {
		System.out.println("Address: \t" + credentials.getAddress());
		System.out.println("HexAddr: \t" + Util.getHexAddress(credentials.getAddress()));
		System.out.println("PrivKey: \t" + ByteArray.toHexString(credentials.getEcKeyPair().getPrivKey().toByteArray()));
	}

	@KeyCommand(value = "help", desc = "Show Help Message")
	private void help(String[] array) {
		System.out.println("You can enter the following command: ");
		if (commandMap.size() > 0) {
			Iterator<Map.Entry<String, Method>> iterator = commandMap.entrySet().iterator();
			while (iterator.hasNext()) {
				Method me = iterator.next().getValue();
				KeyCommand dec = me.getAnnotation(KeyCommand.class);
				System.out.println(dec.value() + ":" + dec.desc());
			}
		} else {
			System.out.println("GenKeystore");
			System.out.println("ImportPrivatekey");
			System.out.println("Exit or Quit");
		}
		System.out.println("Input any one of then, you will get more tips.");
	}

	@KeyCommand(value = "genManyAddr", desc = "批量生成账号 genManyAddr passwd1 passwd2 passwd3")
	private void genAddresses(String[] args) throws Throwable {
		if (args == null || args.length <= 1) {
			System.out.println("传入密码为空");
			return;
		}
		for (int i = 1; i < args.length; i++) {
			String password = args[i];
			ECKey eCkey = new ECKey(Utils.random);
			File file = new File(FilePath);
			if (!file.exists()) {
				if (!file.mkdir()) {
					throw new IOException("Make directory faild!");
				}
			} else {
				if (!file.isDirectory()) {
					if (file.delete()) {
						if (!file.mkdir()) {
							throw new IOException("Make directory faild!");
						}
					} else {
						throw new IOException("File is exists and can not delete!");
					}
				}
			}
			String fileName = WalletUtils.generateWalletFile(password, eCkey, file, true);
			Credentials credentials = WalletUtils.loadCredentials(password, new File(file, fileName));
			System.out.println("Passwd : \t" + password);
			printCredentialInfo(credentials);
			System.out.println();
		}
	}

	private void run() {
		Scanner in = new Scanner(System.in);
		help(null);
		while (in.hasNextLine()) {
			try {
				String cmdLine = in.nextLine().trim();
				String[] cmdArray = cmdLine.split("\\s+");
				// split on trim() string will always return at the minimum: [""]
				String cmd = cmdArray[0];
				if ("".equals(cmd)) {
					continue;
				}
				String cmdLowerCase = cmd.toLowerCase();
				Method cmdMethod = commandMap.get(cmdLowerCase);
				if (cmdMethod != null) {
					try {
						cmdMethod.invoke(this, (Object) cmdArray);
					} catch (Throwable t) {
						t.printStackTrace();
					}

				} else {
					help(cmdArray);
				}
			} catch (Throwable e) {
				logger.error(e.getMessage());
			}
		}
	}

	@KeyCommand(value = "exit", desc = "Exit|Quit")
	private void exit(String args[]) {
		System.exit(0);
	}

	public static void main(String[] args) {
		Args.setParam(args, Constant.TESTNET_CONF);
		KeystoreFactory cli = new KeystoreFactory();

		JCommander.newBuilder()
				.addObject(cli)
				.build()
				.parse(args);

		cli.run();
	}
}
