/**
 *
 */
package com.googlecode.cas.jaspic.util;

import java.util.Random;

/**
 * @author hisato
 * 
 */
public class TicketGenerator {

	private static final String[] table = {
		"A", "B", "C", "D", "E", "F", "G", "H",
		"I", "J", "K", "L", "M", "N", "O", "P",
		"Q", "R", "S", "T", "U", "V", "W", "X",
		"Y", "Z", "a", "b", "c", "d", "e", "f",
		"g", "h", "i", "j", "k", "l", "m", "n",
		"o", "p", "q", "r", "s", "t", "u", "v",
		"w", "x", "y", "z", "0", "1", "2", "3",
		"4", "5", "6", "7", "8", "9", "+", "/" };

	private static String _suffix = "JT-";

	public static String getSuffix() {
		return _suffix;
	}

	public static void setSuffix(String suffix) {
		_suffix = suffix;
	}

	private static int _maxlength = 20;

	public static int getMaxLength() {
		return _maxlength;
	}

	public static void setgetMaxLength(int maxlength) {
		_maxlength = maxlength;
	}

	public static String generateTicket() {
		byte[] b = new byte[_maxlength];
		new Random().nextBytes(b);
		return _suffix + encode(b);
	}

	public static void main(String[] args) {
		System.out.println(generateTicket());
	}

	private static String encode(byte[] bytes) {
		StringBuffer bit = new StringBuffer();
		for (int i = 0; i < bytes.length; ++i) {
			int b = bytes[i];
			String tmp = Integer.toBinaryString(b < 0 ? b + 256 : b);
			for (int j = tmp.length(); j < 8; j++) {
				bit.append("0");
			}
			bit.append(tmp);
		}
		while (bit.length() % 6 != 0) {
			bit.append("0");
		}
		StringBuffer encoded = new StringBuffer();
		for (int i = 0; i < bit.length(); i += 6) {
			encoded.append(table[Integer.parseInt(bit.substring(i, i + 6), 2)]);
		}
		while (encoded.length() % 4 != 0) {
			encoded.append("=");
		}
		return encoded.toString();
	}

}
