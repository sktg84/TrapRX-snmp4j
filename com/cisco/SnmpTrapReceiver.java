package com.cisco;

import org.snmp4j.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.*;
import org.json.JSONObject;

import net.percederberg.mibble.*;
import net.percederberg.mibble.value.ObjectIdentifierValue;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class SnmpTrapReceiver {

	private static final BlockingQueue<CommandResponderEvent> trapQueue = new LinkedBlockingQueue<>();
	private static final int CONSUMER_THREADS = 3;

	public static void main(String[] args) {
		try {
			MibLoader loader = new MibLoader();
			Mib mib = loader.load(new File("/users/ksubram2/Downloads/STARENT-MIB.mib"));
			TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/162"));
			Snmp snmp = new Snmp(transport);
			transport.listen();
			snmp.addCommandResponder(event -> {
				try {
					trapQueue.put(event);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					e.printStackTrace();
				}
			});

			System.out.println("Listening for SNMP Traps on 0.0.0.0/162...");

			ExecutorService consumerPool = Executors.newFixedThreadPool(CONSUMER_THREADS);
			for (int i = 0; i < CONSUMER_THREADS; i++) {
				consumerPool.submit(() -> processTraps(mib));
			}

			new CountDownLatch(1).await();

		} catch (IOException | InterruptedException | MibLoaderException e) {
			e.printStackTrace();
		}
	}

	// Method for consumers to process traps from the queue
	private static void processTraps(Mib mib) {
		while (true) {
			try {
				CommandResponderEvent event = trapQueue.take(); // Take a trap from the queue
				PDU pdu = event.getPDU();
				if (pdu != null) {
					JSONObject trapJson = new JSONObject();
					String trapName = "Unknown Trap";

					List<? extends VariableBinding> variableBindings = pdu.getVariableBindings();
					for (VariableBinding vb : variableBindings) {
						String oid = vb.getOid().toString();
						String value = vb.getVariable().toString();

						if (oid.equals("1.3.6.1.6.3.1.1.4.1.0")) {
							trapName = resolveOidToName(value, mib);
						} else {
							String paramName = resolveOidToName(oid, mib);
							trapJson.put(paramName != null ? paramName : oid, value);
						}
					}
				    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

					trapJson.put("trapName", trapName);
	                String currentTime = LocalDateTime.now().format(formatter);

	                System.out.println("[" + currentTime + "] Thread [" + Thread.currentThread().getName() + "] Processed Trap: " + trapJson.toString(4));

				}
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				e.printStackTrace();
			}
		}
	}

	private static String resolveOidToName(String oid, Mib mib) {
		try {
			if (oid.equals("1.3.6.1.2.1.1.3.0"))
				return "sysUpTime";

			String name = resolveOidDirectly(oid, mib);
			if (name != null) {
				return name;
			}

			if (oid.endsWith(".0")) {
				String trimmedOid = oid.substring(0, oid.length() - 2);
				name = resolveOidDirectly(trimmedOid, mib);
				if (name != null) {
					return name;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("Could not resolve OID " + oid);
		return null;
	}

	private static String resolveOidDirectly(String oid, Mib mib) {
		for (MibSymbol symbol : mib.getAllSymbols()) {
			if (symbol instanceof MibValueSymbol) {
				MibValueSymbol valueSymbol = (MibValueSymbol) symbol;
				if (valueSymbol.getValue() instanceof ObjectIdentifierValue) {
					ObjectIdentifierValue objIdVal = (ObjectIdentifierValue) valueSymbol.getValue();
					if (objIdVal.toString().equals(oid)) {
//                        System.out.println("Resolved OID " + oid + " to name: " + valueSymbol.getName());
						return valueSymbol.getName();
					}
				}
			}
		}
		return null;
	}
}
