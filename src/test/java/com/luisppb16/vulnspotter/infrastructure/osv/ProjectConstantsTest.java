/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.osv;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import org.junit.jupiter.api.Test;

class ProjectConstantsTest {

  @Test
  void testConstants() {
    assertEquals("https://api.osv.dev/v1/querybatch", ProjectConstants.OSV_API_BATCH_URL);
    assertEquals("https://api.osv.dev/v1/vulns/", ProjectConstants.OSV_API_VULNS_URL);
    assertEquals("https://osv.dev/vulnerability/", ProjectConstants.OSV_WEB_VULN_URL);
    assertEquals("https://nvd.nist.gov/vuln/detail/", ProjectConstants.NVD_VULN_URL);
  }

  @Test
  void testPrivateConstructor() throws NoSuchMethodException {
    Constructor<ProjectConstants> constructor = ProjectConstants.class.getDeclaredConstructor();
    assertTrue(Modifier.isPrivate(constructor.getModifiers()));
    constructor.setAccessible(true);
    try {
      constructor.newInstance();
      fail("Expected InvocationTargetException");
    } catch (InvocationTargetException e) {
      assertInstanceOf(UnsupportedOperationException.class, e.getCause());
    } catch (InstantiationException | IllegalAccessException e) {
      fail("Unexpected exception: " + e);
    }
  }
}
