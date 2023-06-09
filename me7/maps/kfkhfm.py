""" 


public Collection<? extends LocatedMap> locateMaps(byte[] binary) {
    Set<LocatedMap> locatedMaps = new HashSet<LocatedMap>();
    Stack<String> patterns = new Stack<String>();
    
    // KFKHFM    
    // 1.8T wideband
    patterns.push("E6 XX MMXX XX C2 XX XX XX C2 XX XX XX DA 00 XX XX F7 XX XX XX C0 84 5C 74");
    
    
    int address = PatternMatcher.findPattern("E6 XX MMXX XX C2 XX XX XX C2 XX XX XX DA 00 XX XX F7 XX XX XX C0 84 5C 74", binary);
    
    if (address != -1) {
      address = 0x204 * 0x4000 - 0x800000 + Me7JavaPlugin.getInt(binary, address);
      
      LocatedMap map = new LocatedMap();
      map.setId("KFKHFM");
      map.setAddress(address + binary[address] + binary[address+1] + 2);
      map.setFactor(0.007813d);
      map.setWidth(1);
      
      // RPM
      LocatedMap yAxis = new LocatedMap();
      yAxis.setId("KFKHFM_Y");
      yAxis.setAddress(address + 2);
      yAxis.setLength(binary[address]);
      yAxis.setFactor(40d);
      yAxis.setWidth(1);
      
      // Load
      LocatedMap xAxis = new LocatedMap();
      xAxis.setId("KFKHFM_X");
      xAxis.setAddress(address + binary[address] + 2);
      xAxis.setLength(binary[address+1]);
      xAxis.setFactor(0.75d);
      xAxis.setWidth(1);
      
      map.setxAxis(xAxis);
      map.setyAxis(yAxis);
      
      locatedMaps.add(map);
      locatedMaps.add(xAxis);
      locatedMaps.add(yAxis);
    }


"""