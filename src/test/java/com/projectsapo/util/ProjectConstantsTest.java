/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.VulnSpotter.util;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import org.junit.jupiter.api.Test;

class ProjectConstantsTest {

  @Test
  void testConstants() {
    assertEquals("https://api.osv.dev/v1/query", ProjectConstants.OSV_API_URL);
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
