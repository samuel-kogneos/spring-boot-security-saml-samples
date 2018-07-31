package com.ulisesbocchio.security.saml.config;

import lombok.SneakyThrows;
import org.joda.time.DateTime;
import org.opensaml.util.resource.ResourceException;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;

/**
 * Wraps Spring resource into OpenSAML resource.
 */
public class SpringResourceWrapper implements org.opensaml.util.resource.Resource {

    private Resource springDelegate;

    public SpringResourceWrapper(Resource springDelegate) throws ResourceException {
        this.springDelegate = springDelegate;
        exists();
    }

    @Override
    @SneakyThrows
    public String getLocation() {
        return springDelegate.getURL().toString();
    }

    @Override
    public boolean exists() throws ResourceException {
        return springDelegate.exists();
    }

    @Override
    public InputStream getInputStream() throws ResourceException {
        try {
            return springDelegate.getInputStream();
        } catch (IOException e) {
            throw new ResourceException(e);
        }
    }

    @Override
    public DateTime getLastModifiedTime() throws ResourceException {
        try {
            return new DateTime(springDelegate.lastModified());
        } catch (IOException e) {
            throw new ResourceException(e);
        }
    }

    public int hashCode() {
        return getLocation().hashCode();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof SpringResourceWrapper) {
            return getLocation().equals(((SpringResourceWrapper) o).getLocation());
        }

        return false;
    }
}
